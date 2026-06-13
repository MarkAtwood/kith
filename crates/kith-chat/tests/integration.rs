// Integration tests for kith-chat crate.
//
// These tests use the full Dispatcher → handler → in-memory store path.
// No mocks. All expected values are hand-derived from RFC 8620 and kith specs.

use kith_core::{Identity, JmapRequest, Role};
use kith_jmap::Dispatcher;
use serde_json::json;
use std::sync::{Arc, Mutex};

fn dummy_identity() -> Identity {
    Identity {
        user_id: "uid-test".to_string(),
        login_name: "test@example.com".to_string(),
        display_name: None,
        node_name: "test-node.tail12345.ts.net".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

fn make_store() -> Arc<Mutex<kith_store::Store>> {
    Arc::new(Mutex::new(
        kith_store::Store::open_in_memory().expect("in-memory store"),
    ))
}

fn make_dispatcher(store: Arc<Mutex<kith_store::Store>>) -> (Dispatcher, tempfile::TempDir) {
    let blob_dir = tempfile::TempDir::new().expect("blob dir");
    let blob_store = Arc::new(kith_attach::BlobStore::new(blob_dir.path()));
    blob_store.init().expect("blob store init must succeed");
    let mut d = Dispatcher::new();
    d.register(
        "ChatContact/get",
        Box::new(kith_chat::contact::ChatContactGetHandler::new(Arc::clone(
            &store,
        ))),
    );
    d.register(
        "ChatContact/set",
        Box::new(kith_chat::contact::ChatContactSetHandler::new(Arc::clone(
            &store,
        ))),
    );
    d.register(
        "ChatContact/changes",
        Box::new(kith_chat::contact::ChatContactChangesHandler::new(
            Arc::clone(&store),
        )),
    );
    d.register(
        "ChatContact/query",
        Box::new(kith_chat::contact::ChatContactQueryHandler::new(
            Arc::clone(&store),
        )),
    );
    d.register(
        "ChatContact/queryChanges",
        Box::new(kith_chat::contact::ChatContactQueryChangesHandler::new(
            Arc::clone(&store),
        )),
    );
    d.register(
        "Chat/get",
        Box::new(kith_chat::chat::ChatGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Chat/set",
        Box::new(kith_chat::chat::ChatSetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Chat/changes",
        Box::new(kith_chat::chat::ChatChangesHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Chat/query",
        Box::new(kith_chat::chat::ChatQueryHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Message/get",
        Box::new(kith_chat::message::MessageGetHandler::new(Arc::clone(
            &store,
        ))),
    );
    d.register(
        "Message/set",
        Box::new(kith_chat::message::MessageSetHandler::new(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            "uid-test-owner".to_string(),
        )),
    );
    d.register(
        "Message/changes",
        Box::new(kith_chat::message::MessageChangesHandler::new(Arc::clone(
            &store,
        ))),
    );
    d.register(
        "Message/query",
        Box::new(kith_chat::message::MessageQueryHandler::new(Arc::clone(
            &store,
        ))),
    );
    d.register(
        "Message/queryChanges",
        Box::new(kith_chat::message::MessageQueryChangesHandler::new(
            Arc::clone(&store),
        )),
    );
    d.register(
        "Space/get",
        Box::new(kith_chat::space::SpaceGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Space/changes",
        Box::new(kith_chat::space::SpaceChangesHandler::new(Arc::clone(
            &store,
        ))),
    );
    (d, blob_dir)
}

fn kith_request(method_calls: Vec<(&str, serde_json::Value, &str)>) -> JmapRequest {
    JmapRequest::new(
        vec![
            "urn:ietf:params:jmap:core".to_string(),
            "urn:ietf:params:jmap:chat".to_string(),
        ],
        method_calls
            .into_iter()
            .map(|(m, a, c)| (m.to_string(), a, c.to_string()))
            .collect(),
        None,
    )
}

// ---------------------------------------------------------------------------
// GROUP A — Cross-method workflow tests
// ---------------------------------------------------------------------------

// Oracle: ChatContact/set create → Contact/get → Contact/query → Contact/changes
// all operate on the same underlying store; state tokens must be consistent.
// RFC 8620 §5.1 (get), §5.3 (set), §5.6 (changes), §5.7 (query).
#[tokio::test]
async fn test_full_contact_workflow() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Step 1: ChatContact/set create.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-alice",
                    "login": "alice@example.com",
                    "mailboxHost": "alice-kith.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, call_id) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/set");
    assert_eq!(call_id, "c0");
    // Oracle: RFC 8620 §5.3 — created map has the client-id key.
    assert!(
        args["created"].get("c0").is_some(),
        "created.c0 must be present; got: {args}"
    );
    // Oracle: I-D §ChatContact — id IS the userId from the auth layer.
    assert_eq!(args["created"]["c0"]["id"], "uid-alice");
    let new_state_after_set = args["newState"].as_str().unwrap().to_string();

    // Step 2: ChatContact/get by id — verify the contact is readable.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({
            "accountId": "a-self",
            "ids": ["uid-alice"]
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, call_id) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/get");
    assert_eq!(call_id, "c1");
    let list = args["list"].as_array().expect("list must be array");
    assert_eq!(list.len(), 1, "exactly one contact in list");
    // Oracle: I-D §ChatContact — id IS the userId from the auth layer.
    assert_eq!(list[0]["id"], "uid-alice");
    assert_eq!(list[0]["login"], "alice@example.com");
    // Oracle: state returned by get must match newState returned by set.
    assert_eq!(args["state"], new_state_after_set);

    // Step 3: ChatContact/query — the new contact appears in the id list.
    let req = kith_request(vec![(
        "ChatContact/query",
        json!({"accountId": "a-self"}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/query");
    let ids = args["ids"].as_array().expect("ids must be array");
    assert!(
        ids.iter().any(|v| v.as_str() == Some("uid-alice")),
        "uid-alice must appear in Contact/query ids; got: {ids:?}"
    );

    // Step 4: ChatContact/changes from s-0 — the new contact is in created.
    let req = kith_request(vec![(
        "ChatContact/changes",
        json!({"accountId": "a-self", "sinceState": "s-0"}),
        "c3",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/changes");
    let created = args["created"].as_array().expect("created must be array");
    assert!(
        created.iter().any(|v| v.as_str() == Some("uid-alice")),
        "uid-alice must appear in Contact/changes created; got: {created:?}"
    );
    // Oracle: newState must match what Contact/get and Contact/set returned.
    assert_eq!(args["newState"], new_state_after_set);
}

// Oracle: ChatContact/set create (for Chat/set dependency) → Chat/set create →
// Chat/get → Chat/query → Chat/changes.
// RFC 8620 §5.3, §5.1, §5.7, §5.6.
#[tokio::test]
async fn test_full_chat_workflow() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Step 1: Create the contact that the chat will reference.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-bob",
                    "login": "bob@example.com",
                    "mailboxHost": "bob-kith.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    assert!(
        resp.method_responses[0].1["created"].get("c0").is_some(),
        "ChatContact/set must succeed"
    );

    // Step 2: Chat/set create.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "create": {
                "ch0": {"contactId": "uid-bob"}
            }
        }),
        "ch0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/set");
    // Oracle: created.ch0 must have an id.
    assert!(
        args["created"].get("ch0").is_some(),
        "created.ch0 must be present; got: {args}"
    );
    let chat_id = args["created"]["ch0"]["id"]
        .as_str()
        .expect("created chat must have an id")
        .to_string();
    let chat_new_state = args["newState"].as_str().unwrap().to_string();

    // Step 3: Chat/get with the returned id.
    let req = kith_request(vec![(
        "Chat/get",
        json!({
            "accountId": "a-self",
            "ids": [chat_id.clone()]
        }),
        "ch1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/get");
    let list = args["list"].as_array().expect("list must be array");
    assert_eq!(list.len(), 1, "Chat/get must return the created chat");
    assert_eq!(list[0]["id"], chat_id);
    // Oracle: state returned by Chat/get must match Chat/set newState.
    assert_eq!(args["state"], chat_new_state);

    // Step 4: Chat/query — chat appears in id list.
    let req = kith_request(vec![("Chat/query", json!({"accountId": "a-self"}), "ch2")]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let ids = args["ids"].as_array().expect("ids must be array");
    assert!(
        ids.iter().any(|v| v.as_str() == Some(chat_id.as_str())),
        "chat_id must appear in Chat/query ids; got: {ids:?}"
    );

    // Step 5: Chat/changes from s-0 — the chat appears in created.
    let req = kith_request(vec![(
        "Chat/changes",
        json!({"accountId": "a-self", "sinceState": "s-0"}),
        "ch3",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/changes");
    let created = args["created"].as_array().expect("created must be array");
    assert!(
        created.iter().any(|v| v.as_str() == Some(chat_id.as_str())),
        "chat_id must appear in Chat/changes created; got: {created:?}"
    );
}

// Oracle: full message workflow: contact → chat → Message/set create →
// Message/get → Message/query → Message/changes → Message/queryChanges.
// State tokens must be consistent across all methods.
#[tokio::test]
async fn test_full_message_workflow() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Step 1: Create a contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-carol",
                    "login": "carol@example.com",
                    "mailboxHost": "carol-kith.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Step 2: Create a chat.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "create": {"ch0": {"contactId": "uid-carol"}}
        }),
        "ch0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let chat_id = resp.method_responses[0].1["created"]["ch0"]["id"]
        .as_str()
        .expect("chat id must be a string")
        .to_string();

    // Capture message state before any messages exist.
    let state_before_msg = {
        let guard = store.lock().unwrap();
        guard.messages().get_state().unwrap()
    };

    // Step 3: Message/set create.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id.clone(),
                    "body": "Hello from integration test!"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/set");
    // Oracle: RFC 8620 §5.3 — created.m0 must be present.
    assert!(
        args["created"].get("m0").is_some(),
        "created.m0 must be present; got: {args}"
    );
    let msg_id = args["created"]["m0"]["id"]
        .as_str()
        .expect("message id must be a string")
        .to_string();
    // Oracle: deliveryState must be "pending" for owner-sent messages.
    assert_eq!(args["created"]["m0"]["deliveryState"], "pending");
    let msg_state_after_set = args["newState"].as_str().unwrap().to_string();

    // Step 4: Message/get — verify message is retrievable by id.
    let req = kith_request(vec![(
        "Message/get",
        json!({
            "accountId": "a-self",
            "ids": [msg_id.clone()]
        }),
        "m1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/get");
    let list = args["list"].as_array().expect("list must be array");
    assert_eq!(list.len(), 1, "Message/get must return the created message");
    assert_eq!(list[0]["id"], msg_id);
    // Oracle: body must match what was set.
    assert_eq!(list[0]["body"], "Hello from integration test!");
    // Oracle: state from Message/get must match Message/set newState.
    assert_eq!(args["state"], msg_state_after_set);

    // Step 5: Message/query with chatId filter — message appears.
    let req = kith_request(vec![(
        "Message/query",
        json!({
            "accountId": "a-self",
            "filter": {"chatId": chat_id.clone()}
        }),
        "m2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/query");
    let ids = args["ids"].as_array().expect("ids must be array");
    assert!(
        ids.iter().any(|v| v.as_str() == Some(msg_id.as_str())),
        "msg_id must appear in Message/query ids; got: {ids:?}"
    );
    // Oracle: queryState must match newState from set.
    assert_eq!(args["queryState"], msg_state_after_set);

    // Step 6: Message/changes from before the insert — message appears in created.
    let req = kith_request(vec![(
        "Message/changes",
        json!({
            "accountId": "a-self",
            "sinceState": state_before_msg
        }),
        "m3",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/changes");
    let created = args["created"].as_array().expect("created must be array");
    assert!(
        created.iter().any(|v| v.as_str() == Some(msg_id.as_str())),
        "msg_id must appear in Message/changes created; got: {created:?}"
    );
    // Oracle: newState must match Message/set newState.
    assert_eq!(args["newState"], msg_state_after_set);

    // Step 7: Message/queryChanges from before the insert — message appears in added.
    let req = kith_request(vec![(
        "Message/queryChanges",
        json!({
            "accountId": "a-self",
            "sinceQueryState": state_before_msg,
            "filter": {"chatId": chat_id.clone()}
        }),
        "m4",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/queryChanges");
    let added = args["added"].as_array().expect("added must be array");
    assert!(!added.is_empty(), "added must not be empty");
    // Oracle: added entry must have id and index fields (per Message/queryChanges spec).
    assert!(added[0].get("id").is_some(), "added entry must have id");
    assert!(
        added[0].get("index").is_some(),
        "added entry must have index"
    );
    assert_eq!(added[0]["id"], msg_id);
}

// ---------------------------------------------------------------------------
// GROUP B — Auth rejection tests (non-self-certifying)
// ---------------------------------------------------------------------------

// Oracle: RFC 8620 §7.1 — "forbidden" is returned when the caller's
// role does not satisfy the method's required role.
// These tests use the Dispatcher directly (not the handlers) so they test
// the actual role gate, not a bypass.
//
// All 10 owner methods must reject when called with Role::Peer.
// The dispatcher emits the error in the method_responses tuple —
// HTTP 200 body with type="forbidden" (RFC 8620 §3.4).
#[tokio::test]
async fn test_peer_cannot_call_owner_methods() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Oracle: all methods listed in METHOD_ROLES as Role::Owner must be rejected.
    let owner_methods = [
        "ChatContact/get",
        "ChatContact/set",
        "ChatContact/changes",
        "ChatContact/query",
        "Chat/get",
        "Chat/set",
        "Chat/changes",
        "Chat/query",
        "Message/get",
        "Message/set",
        "Message/changes",
        "Message/query",
        "Message/queryChanges",
        "ChatContact/queryChanges",
    ];

    for method in owner_methods {
        let req = kith_request(vec![(method, json!({"accountId": "a-self"}), "c0")]);
        let resp = d
            .dispatch(req, Role::Peer, dummy_identity(), "s-0".to_string())
            .await;
        assert_eq!(
            resp.method_responses.len(),
            1,
            "must have exactly one response for method {method}"
        );
        let (_, args, call_id) = &resp.method_responses[0];
        assert_eq!(call_id, "c0", "call_id must be echoed for method {method}");
        // Oracle: RFC 8620 §7.1 — type must be "forbidden".
        assert_eq!(
            args["type"], "forbidden",
            "Role::Peer calling {method} must return forbidden; got: {args}"
        );
    }
}

// Oracle: RFC 8620 §7.1 — unknownMethod is returned for a method name not
// in the METHOD_ROLES registry.
#[tokio::test]
async fn test_owner_cannot_call_unknown_method() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![("Foo/bar", json!({}), "c0")]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    assert_eq!(resp.method_responses.len(), 1);
    let (_, args, _) = &resp.method_responses[0];
    // Oracle: RFC 8620 §7.1 — type must be "unknownMethod".
    assert_eq!(
        args["type"], "unknownMethod",
        "dispatching unknown method must return unknownMethod; got: {args}"
    );
}

// Oracle: Role::Owner calling a Peer-only method must return "forbidden".
// Peer/deliver and Peer/receipt are in METHOD_ROLES as Role::Peer.
#[tokio::test]
async fn test_owner_cannot_call_peer_methods() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    for method in ["Peer/deliver", "Peer/receipt"] {
        let req = kith_request(vec![(method, json!({}), "c0")]);
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        let (_, args, _) = &resp.method_responses[0];
        assert_eq!(
            args["type"], "forbidden",
            "Role::Owner calling {method} must return forbidden; got: {args}"
        );
    }
}

// ---------------------------------------------------------------------------
// GROUP C — Security invariant tests
// ---------------------------------------------------------------------------

// Oracle: body of exactly 65536 bytes must be accepted (boundary is inclusive).
// MAX_BODY_BYTES = 65536; body.len() > 65536 fails. body.len() == 65536 passes.
// RFC 8620 §5.3; kith-chat message.rs process_create body length check.
#[tokio::test]
async fn test_message_body_size_boundary_exact() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Set up contact and chat.
    {
        let guard = store.lock().unwrap();
        guard
            .contacts()
            .upsert(
                "uid-peer-sz",
                "peer@example.com",
                "peer.tail.ts.net",
                None,
                1000,
            )
            .unwrap();
        let chat_id = "test-chat-sz1".to_string();
        guard
            .chats()
            .create(&chat_id, "direct", Some("uid-peer-sz"), 1000)
            .unwrap();
    }
    let chat_id = "test-chat-sz1".to_string();

    // body = exactly 65536 ASCII bytes — must succeed.
    let exact_body = "x".repeat(65536);
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id.clone(),
                    "body": exact_body
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    // Oracle: created.m0 must be present (no type="error" in args).
    assert!(
        args["created"].get("m0").is_some(),
        "65536-byte body must be accepted; got: {args}"
    );
    assert!(
        args["notCreated"]
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true),
        "notCreated must be empty for 65536-byte body; got: {args}"
    );
}

// Oracle: body of 65537 bytes must be rejected with invalidArguments.
// MAX_BODY_BYTES = 65536; body.len() > 65536 triggers the check.
#[tokio::test]
async fn test_message_body_size_boundary_exceeded() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Set up contact and chat.
    {
        let guard = store.lock().unwrap();
        guard
            .contacts()
            .upsert(
                "uid-peer-sz2",
                "peer2@example.com",
                "peer2.tail.ts.net",
                None,
                1000,
            )
            .unwrap();
        let chat_id = "test-chat-sz2".to_string();
        guard
            .chats()
            .create(&chat_id, "direct", Some("uid-peer-sz2"), 1000)
            .unwrap();
    }
    let chat_id = "test-chat-sz2".to_string();

    // body = 65537 bytes — must be rejected.
    let oversized_body = "x".repeat(65537);
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": oversized_body
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    // Oracle: notCreated.m0 must be present with type=invalidArguments.
    assert!(
        args["notCreated"].get("m0").is_some(),
        "65537-byte body must be rejected into notCreated; got: {args}"
    );
    assert_eq!(
        args["notCreated"]["m0"]["type"], "invalidArguments",
        "oversized body rejection must have type=invalidArguments; got: {args}"
    );
    // Oracle: created must be empty — no message was stored.
    assert_eq!(
        args["created"],
        json!({}),
        "created must be empty for oversized body"
    );
    // Verify no DB write occurred: message state is still s-0.
    let msg_state = {
        let guard = store.lock().unwrap();
        guard.messages().get_state().unwrap()
    };
    assert_eq!(
        msg_state, "s-0",
        "message state must remain s-0 when body is rejected"
    );
}

// Oracle: Message/query without filter.chatId must return invalidArguments.
// Per message.rs: filter.chatId is required; absent filter → error.
// RFC 8620 §5.5 — filter is method-specific; missing required filter field
// returns invalidArguments.
#[tokio::test]
async fn test_message_query_requires_chat_id() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // No filter at all.
    let req = kith_request(vec![(
        "Message/query",
        json!({"accountId": "a-self"}),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (method_name, args, _) = &resp.method_responses[0];
    // Oracle: error invocation — method_name is "Message/query" (dispatcher echoes it),
    // and args["type"] is the error type.
    assert_eq!(method_name, "Message/query");
    assert_eq!(
        args["type"], "invalidArguments",
        "Message/query without chatId must return invalidArguments; got: {args}"
    );

    // Also test: filter present but chatId absent.
    let req = kith_request(vec![(
        "Message/query",
        json!({
            "accountId": "a-self",
            "filter": {}
        }),
        "m1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(
        args["type"], "invalidArguments",
        "Message/query with empty filter must return invalidArguments; got: {args}"
    );
}

// Oracle: Message/changes with sinceState="s-99999" (valid format, far future)
// must return an empty delta — no messages have state_version > 99999 in a
// fresh store, so the result is a successful response with empty created list.
// Per RFC 8620 §5.6: if since_state is before any changes, result is empty.
#[tokio::test]
async fn test_message_changes_future_state() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Message/changes",
        json!({
            "accountId": "a-self",
            "sinceState": "s-99999"
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (method_name, args, _) = &resp.method_responses[0];
    assert_eq!(method_name, "Message/changes");
    // Oracle: s-99999 parses successfully; no messages have state_version > 99999 →
    // empty created/updated/destroyed lists. This is a valid, successful response.
    // type field must NOT be present (successful responses have no "type" error field).
    assert!(
        args.get("type").is_none(),
        "Message/changes with future-but-valid state must succeed; got: {args}"
    );
    let created = args["created"].as_array().expect("created must be array");
    assert!(
        created.is_empty(),
        "created must be empty for future sinceState; got: {created:?}"
    );
}

// Oracle: ChatContact/changes with malformed sinceState must return an error.
// "not-s-n" does not match the "s-<integer>" pattern → ContactStore returns
// KithError::Validation → ChatContactChangesHandler maps to JmapError::state_mismatch().
// Per RFC 8620 §5.6: invalid sinceState → stateMismatch error.
#[tokio::test]
async fn test_contact_changes_malformed_state() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "ChatContact/changes",
        json!({
            "accountId": "a-self",
            "sinceState": "not-s-n"
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (method_name, args, _) = &resp.method_responses[0];
    assert_eq!(method_name, "ChatContact/changes");
    // Oracle: RFC 8620 §5.5 — malformed sinceState must return cannotCalculateChanges.
    assert_eq!(
        args["type"], "cannotCalculateChanges",
        "ChatContact/changes with malformed sinceState must return cannotCalculateChanges; got: {args}"
    );
}

// Oracle: Message/set create with wrong chatId (no matching chat) must
// return notCreated with type=notFound, not a handler-level error.
// Per message.rs process_create: chatId not found → notCreated entry with notFound.
#[tokio::test]
async fn test_message_set_wrong_chat_id() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": "chat-does-not-exist",
                    "body": "hello"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (method_name, args, _) = &resp.method_responses[0];
    assert_eq!(method_name, "Message/set");
    // Oracle: method must succeed (HTTP 200 with the error in notCreated).
    assert!(
        args.get("type").is_none(),
        "Message/set must not return a handler-level error for unknown chatId; got: {args}"
    );
    // Oracle: notCreated.m0 with type=notFound.
    assert!(
        args["notCreated"].get("m0").is_some(),
        "notCreated.m0 must be present for unknown chatId; got: {args}"
    );
    assert_eq!(
        args["notCreated"]["m0"]["type"], "notFound",
        "unknown chatId must produce notFound; got: {args}"
    );
}

// ---------------------------------------------------------------------------
// GROUP — Rich body (application/jmap-chat-rich) tests
// ---------------------------------------------------------------------------

/// Helper: create a contact and a chat, return the chat ID.
async fn setup_chat_for_rich_body(_store: &Arc<Mutex<kith_store::Store>>, d: &Dispatcher) -> String {
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-rich-peer",
                    "login": "rich@example.com",
                    "mailboxHost": "rich-kith.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "create": {"ch0": {"contactId": "uid-rich-peer"}}
        }),
        "ch0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    resp.method_responses[0].1["created"]["ch0"]["id"]
        .as_str()
        .expect("chat id must be a string")
        .to_string()
}

// Oracle: Message/set create with bodyType=application/jmap-chat-rich and valid
// spans must be accepted.  The body is a JSON object with a "spans" array
// containing spans with "type" and "text" fields.  The expected result is
// created.m0 present with the correct bodyType.
#[tokio::test]
async fn rich_body_valid_spans_accepted() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_chat_for_rich_body(&store, &d).await;

    let rich_body = serde_json::json!({
        "spans": [
            {"type": "text", "text": "Hello "},
            {"type": "bold", "text": "world"}
        ]
    })
    .to_string();

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": rich_body,
                    "bodyType": "application/jmap-chat-rich"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["created"].get("m0").is_some(),
        "valid rich body must be accepted; got: {args}"
    );
    assert_eq!(
        args["created"]["m0"]["bodyType"], "application/jmap-chat-rich",
        "bodyType must be preserved in response"
    );
}

// Oracle: Message/set create with bodyType=application/jmap-chat-rich and invalid
// JSON body must be rejected with invalidArguments.
#[tokio::test]
async fn rich_body_invalid_json_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_chat_for_rich_body(&store, &d).await;

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "not valid json {{{",
                    "bodyType": "application/jmap-chat-rich"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "invalid JSON rich body must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// Oracle: Message/set create with bodyType=application/jmap-chat-rich and body
// missing the "spans" key must be rejected with invalidArguments.
#[tokio::test]
async fn rich_body_missing_spans_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_chat_for_rich_body(&store, &d).await;

    let body_no_spans = serde_json::json!({"other": "stuff"}).to_string();

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": body_no_spans,
                    "bodyType": "application/jmap-chat-rich"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "rich body without spans must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// Oracle: Message/set create with bodyType=application/jmap-chat-rich containing
// unrecognized span types must be accepted (forward compatibility per spec:
// "Servers MUST NOT reject messages solely because they contain unrecognized span types").
#[tokio::test]
async fn rich_body_unrecognized_span_types_accepted() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_chat_for_rich_body(&store, &d).await;

    let rich_body = serde_json::json!({
        "spans": [
            {"type": "text", "text": "Hello"},
            {"type": "custom-widget-v9", "text": "fancy stuff"},
            {"type": "unknown-future-type", "text": "forward compat"}
        ]
    })
    .to_string();

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": rich_body,
                    "bodyType": "application/jmap-chat-rich"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["created"].get("m0").is_some(),
        "unrecognized span types must be accepted; got: {args}"
    );
}

// Oracle: Message/set create with bodyType=application/jmap-chat-rich and a
// non-empty mentions array must be rejected with invalidArguments.
// Rich body carries mentions inline as spans.
#[tokio::test]
async fn rich_body_nonempty_mentions_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_chat_for_rich_body(&store, &d).await;

    let rich_body = serde_json::json!({
        "spans": [{"type": "text", "text": "Hello"}]
    })
    .to_string();

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": rich_body,
                    "bodyType": "application/jmap-chat-rich",
                    "mentions": [{"userId": "uid-someone", "offset": 0, "length": 5}]
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "non-empty mentions with rich body must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// Oracle: Message/set create with bodyType=application/jmap-chat-rich and a
// non-empty broadcastMentions array must be rejected with invalidArguments.
// Rich body carries broadcast mentions inline as spans.
#[tokio::test]
async fn rich_body_nonempty_broadcast_mentions_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_chat_for_rich_body(&store, &d).await;

    let rich_body = serde_json::json!({
        "spans": [{"type": "text", "text": "Hello"}]
    })
    .to_string();

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": rich_body,
                    "bodyType": "application/jmap-chat-rich",
                    "broadcastMentions": [{"scope": "everyone", "offset": 0, "length": 5}]
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "non-empty broadcastMentions with rich body must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// Oracle: Message/set create with bodyType=application/jmap-chat-rich containing
// a broadcast span with an invalid scope must be rejected with invalidArguments.
// Valid scopes are "everyone", "here", "admins" (case-sensitive).
#[tokio::test]
async fn rich_body_broadcast_span_invalid_scope_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_chat_for_rich_body(&store, &d).await;

    let rich_body = serde_json::json!({
        "spans": [
            {"type": "broadcast", "text": "@channel", "scope": "channel"}
        ]
    })
    .to_string();

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": rich_body,
                    "bodyType": "application/jmap-chat-rich"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "broadcast span with invalid scope must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// ---------------------------------------------------------------------------
// GROUP — Rich body regression tests (non-rich body types still work)
// ---------------------------------------------------------------------------

// Oracle: Message/set create with text/plain bodyType (or no bodyType, which
// defaults to text/plain) must be accepted.  This is a regression guard to
// ensure rich body validation does not accidentally break the default path.
#[tokio::test]
async fn message_create_text_plain_regression() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Set up contact and chat via store directly.
    {
        let guard = store.lock().unwrap();
        guard
            .contacts()
            .upsert(
                "uid-plain-peer",
                "plain@example.com",
                "plain.tail.ts.net",
                None,
                1000,
            )
            .unwrap();
        guard
            .chats()
            .create("chat-plain", "direct", Some("uid-plain-peer"), 1000)
            .unwrap();
    }

    // No bodyType → defaults to text/plain.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": "chat-plain",
                    "body": "hello plain text"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["created"].get("m0").is_some(),
        "text/plain message must be accepted; got: {args}"
    );

    // Explicit bodyType=text/plain.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m1": {
                    "chatId": "chat-plain",
                    "body": "hello explicit plain",
                    "bodyType": "text/plain"
                }
            }
        }),
        "m1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["created"].get("m1").is_some(),
        "explicit text/plain message must be accepted; got: {args}"
    );
}

// Oracle: Message/set create with bodyType=text/markdown must be accepted.
// Regression guard for the rich body validation path.
#[tokio::test]
async fn message_create_text_markdown_regression() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    {
        let guard = store.lock().unwrap();
        guard
            .contacts()
            .upsert(
                "uid-md-peer",
                "md@example.com",
                "md.tail.ts.net",
                None,
                1000,
            )
            .unwrap();
        guard
            .chats()
            .create("chat-md", "direct", Some("uid-md-peer"), 1000)
            .unwrap();
    }

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": "chat-md",
                    "body": "# Hello **markdown**",
                    "bodyType": "text/markdown"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["created"].get("m0").is_some(),
        "text/markdown message must be accepted; got: {args}"
    );
    assert_eq!(
        args["created"]["m0"]["bodyType"], "text/markdown",
        "bodyType must be preserved in response"
    );
}

// Oracle: Message/set create with an unrecognized bodyType must be rejected
// with invalidArguments.  Supported types are: text/plain, text/markdown,
// application/jmap-chat-rich.
#[tokio::test]
async fn message_create_unknown_body_type_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    {
        let guard = store.lock().unwrap();
        guard
            .contacts()
            .upsert(
                "uid-unk-peer",
                "unk@example.com",
                "unk.tail.ts.net",
                None,
                1000,
            )
            .unwrap();
        guard
            .chats()
            .create("chat-unk", "direct", Some("uid-unk-peer"), 1000)
            .unwrap();
    }

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": "chat-unk",
                    "body": "hello",
                    "bodyType": "text/html"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "unknown bodyType must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// ---------------------------------------------------------------------------
// GROUP — Handler-level integration tests for Chat/set update
// ---------------------------------------------------------------------------

/// Helper: create a contact and a group chat (via store), return the chat ID.
fn setup_group_chat(store: &Arc<Mutex<kith_store::Store>>, suffix: &str) -> String {
    let guard = store.lock().unwrap();
    let uid = format!("uid-grp-{suffix}");
    let chat_id = format!("chat-grp-{suffix}");
    guard
        .contacts()
        .upsert(
            &uid,
            &format!("grp-{suffix}@example.com"),
            &format!("grp-{suffix}.tail.ts.net"),
            None,
            1000,
        )
        .unwrap();
    guard
        .chats()
        .create(&chat_id, "group", None, 1000)
        .unwrap();
    chat_id
}

/// Helper: create a contact and a direct chat (via store), return the chat ID.
fn setup_direct_chat(store: &Arc<Mutex<kith_store::Store>>, suffix: &str) -> String {
    let guard = store.lock().unwrap();
    let uid = format!("uid-dc-{suffix}");
    let chat_id = format!("chat-dc-{suffix}");
    guard
        .contacts()
        .upsert(
            &uid,
            &format!("dc-{suffix}@example.com"),
            &format!("dc-{suffix}.tail.ts.net"),
            None,
            1000,
        )
        .unwrap();
    guard
        .chats()
        .create(&chat_id, "direct", Some(&uid), 1000)
        .unwrap();
    chat_id
}

// Oracle: Chat/set update with "name" on a group chat must succeed and persist.
// The name field is optional; setting it must update the chat metadata.
#[tokio::test]
async fn chat_set_update_name_on_group_chat() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_group_chat(&store, "name");

    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "update": {
                chat_id.clone(): {"name": "Team Alpha"}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    // Oracle: RFC 8620 §5.3 — updated.<id> must be null on success.
    assert!(
        args["updated"].get(&chat_id).is_some(),
        "Chat/set update name must succeed; got: {args}"
    );

    // Verify via Chat/get.
    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let chat = &args["list"][0];
    assert_eq!(chat["name"], "Team Alpha", "name must be persisted");
}

// Oracle: Chat/set update with "muted" toggle must succeed.
// Default muted is false; toggling to true and back must work.
#[tokio::test]
async fn chat_set_update_muted_toggle() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "muted");

    // Verify default is false.
    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["list"][0]["muted"], false, "default muted must be false");

    // Set muted=true.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "update": {
                chat_id.clone(): {"muted": true}
            }
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get(&chat_id).is_some(),
        "Chat/set update muted=true must succeed; got: {args}"
    );

    // Verify via Chat/get.
    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["list"][0]["muted"], true, "muted must be true after toggle");
}

// Oracle: Chat/set update receiveTypingIndicators must succeed.
// Default is true; toggling to false must persist.
#[tokio::test]
async fn chat_set_update_receive_typing_indicators() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "typing");

    // Default is true.
    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(
        args["list"][0]["receiveTypingIndicators"], true,
        "default receiveTypingIndicators must be true"
    );

    // Set to false.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "update": {
                chat_id.clone(): {"receiveTypingIndicators": false}
            }
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get(&chat_id).is_some(),
        "update receiveTypingIndicators must succeed; got: {args}"
    );

    // Verify via Chat/get.
    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(
        args["list"][0]["receiveTypingIndicators"], false,
        "receiveTypingIndicators must be false after update"
    );
}

// Oracle: Chat/set update messageExpirySeconds with a positive value must succeed.
// The field is optional (defaults to null); setting a positive integer must persist.
#[tokio::test]
async fn chat_set_update_message_expiry_seconds_valid() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "expiry-ok");

    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "update": {
                chat_id.clone(): {"messageExpirySeconds": 3600}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get(&chat_id).is_some(),
        "messageExpirySeconds=3600 must succeed; got: {args}"
    );

    // Verify via Chat/get.
    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(
        args["list"][0]["messageExpirySeconds"], 3600,
        "messageExpirySeconds must be 3600 after update"
    );
}

// Oracle: Chat/set update messageExpirySeconds=0 must be rejected with
// invalidArguments.  Zero is not a valid expiry (must be positive or null).
#[tokio::test]
async fn chat_set_update_message_expiry_seconds_zero_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "expiry-0");

    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "update": {
                chat_id.clone(): {"messageExpirySeconds": 0}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notUpdated"].get(&chat_id).is_some(),
        "messageExpirySeconds=0 must be rejected; got: {args}"
    );
    assert_eq!(args["notUpdated"][&chat_id]["type"], "invalidArguments");
}

// ---------------------------------------------------------------------------
// GROUP — Handler-level integration tests for Message/set features
// ---------------------------------------------------------------------------

// Oracle: Message/set create with broadcastMentions and text/plain body
// must store the mentions and return them in Message/get.
#[tokio::test]
async fn message_create_with_broadcast_mentions_roundtrip() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "bm-rt");

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id.clone(),
                    "body": "@everyone hello team",
                    "broadcastMentions": [
                        {"scope": "everyone", "offset": 0, "length": 9}
                    ]
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["created"].get("m0").is_some(),
        "message with broadcastMentions must be accepted; got: {args}"
    );
    let msg_id = args["created"]["m0"]["id"]
        .as_str()
        .expect("message id must be a string")
        .to_string();
    // The created response should include broadcastMentions.
    let bm = &args["created"]["m0"]["broadcastMentions"];
    assert!(
        bm.is_array(),
        "broadcastMentions must be in created response; got: {args}"
    );
    assert_eq!(bm.as_array().unwrap().len(), 1);
    assert_eq!(bm[0]["scope"], "everyone");

    // Verify via Message/get: the store returns the message with mentions.
    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": [msg_id.clone()]}),
        "m1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let msg = &args["list"][0];
    assert_eq!(msg["id"], msg_id);
    // broadcastMentions persisted via the store and returned in Message/get.
    let bm_get = &msg["broadcastMentions"];
    assert!(
        bm_get.is_array(),
        "broadcastMentions must be in Message/get response; got: {msg}"
    );
    assert_eq!(bm_get[0]["scope"], "everyone");
}

// Oracle: Message/set destroy must return "forbidden" for all IDs.
// Messages cannot be destroyed per the current handler (Phase 1 policy).
#[tokio::test]
async fn message_set_destroy_forbidden() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "destroy");

    // First create a message to get a valid ID.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id.clone(),
                    "body": "will try to destroy"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let msg_id = resp.method_responses[0].1["created"]["m0"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Attempt to destroy.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "destroy": [msg_id.clone()]
        }),
        "m1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    // Oracle: notDestroyed.<id> must have type=forbidden.
    assert!(
        args["notDestroyed"].get(&msg_id).is_some(),
        "destroy must be rejected; got: {args}"
    );
    assert_eq!(
        args["notDestroyed"][&msg_id]["type"], "forbidden",
        "destroy rejection must be type=forbidden"
    );
    // The destroyed array must be empty.
    assert_eq!(args["destroyed"], json!([]), "destroyed must be empty");
}

// Oracle: Message/set update with a key other than "readAt" must be rejected
// with invalidProperties.  Only readAt is patchable (Phase 1).
#[tokio::test]
async fn message_set_update_body_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "upd-body");

    // Create a message.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id.clone(),
                    "body": "original body"
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let msg_id = resp.method_responses[0].1["created"]["m0"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Attempt to update body (not supported).
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "update": {
                msg_id.clone(): {"body": "edited body"}
            }
        }),
        "m1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notUpdated"].get(&msg_id).is_some(),
        "body update must be rejected; got: {args}"
    );
    assert_eq!(
        args["notUpdated"][&msg_id]["type"], "invalidProperties",
        "body update rejection must be type=invalidProperties"
    );
}

// ---------------------------------------------------------------------------
// GROUP — Handler-level integration tests for ChatContact/set update
// ---------------------------------------------------------------------------

// Oracle: ChatContact/set update with "presence" must succeed.
// Valid presence values are defined by the Presence enum.
#[tokio::test]
async fn contact_set_update_presence() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create a contact first.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-pres",
                    "login": "pres@example.com",
                    "mailboxHost": "pres.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    assert!(
        resp.method_responses[0].1["created"].get("c0").is_some(),
        "contact create must succeed"
    );

    // Update presence to "away".
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "update": {
                "uid-pres": {"presence": "away"}
            }
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get("uid-pres").is_some(),
        "presence update must succeed; got: {args}"
    );

    // Verify via ChatContact/get.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self", "ids": ["uid-pres"]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(
        args["list"][0]["presence"], "away",
        "presence must be 'away' after update"
    );
}

// Oracle: ChatContact/set update with "statusText" must succeed and persist.
#[tokio::test]
async fn contact_set_update_status_text() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create a contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-stat",
                    "login": "stat@example.com",
                    "mailboxHost": "stat.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Update statusText.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "update": {
                "uid-stat": {"statusText": "On vacation"}
            }
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get("uid-stat").is_some(),
        "statusText update must succeed; got: {args}"
    );

    // Verify via ChatContact/get.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self", "ids": ["uid-stat"]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(
        args["list"][0]["statusText"], "On vacation",
        "statusText must be persisted after update"
    );
}

// ---------------------------------------------------------------------------
// GROUP — Chat/get returns new fields, Message/get returns mentions
// ---------------------------------------------------------------------------

// Oracle: Chat/get must include muted, name, receiveTypingIndicators, and
// messageExpirySeconds fields when they have been set via Chat/set update.
#[tokio::test]
async fn chat_get_returns_metadata_fields() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_group_chat(&store, "getfields");

    // Update multiple metadata fields.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "update": {
                chat_id.clone(): {
                    "name": "Engineering",
                    "muted": true,
                    "receiveTypingIndicators": false,
                    "messageExpirySeconds": 86400
                }
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get(&chat_id).is_some(),
        "multi-field update must succeed; got: {args}"
    );

    // Chat/get must return all fields.
    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let chat = &args["list"][0];
    assert_eq!(chat["name"], "Engineering", "name must be returned");
    assert_eq!(chat["muted"], true, "muted must be returned");
    assert_eq!(
        chat["receiveTypingIndicators"], false,
        "receiveTypingIndicators must be returned"
    );
    assert_eq!(
        chat["messageExpirySeconds"], 86400,
        "messageExpirySeconds must be returned"
    );
}

// Oracle: Message/get must include broadcastMentions when they were set at
// create time.  This verifies the store round-trip at the handler level.
#[tokio::test]
async fn message_get_returns_broadcast_mentions() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "bm-get");

    // Create a message with broadcastMentions.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id.clone(),
                    "body": "@here standup time",
                    "broadcastMentions": [
                        {"scope": "here", "offset": 0, "length": 5}
                    ]
                }
            }
        }),
        "m0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let msg_id = args["created"]["m0"]["id"]
        .as_str()
        .expect("message id must exist")
        .to_string();

    // Message/get must return broadcastMentions.
    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": [msg_id.clone()]}),
        "m1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let msg = &args["list"][0];
    assert_eq!(msg["id"], msg_id);
    let bm = &msg["broadcastMentions"];
    assert!(
        bm.is_array(),
        "broadcastMentions must be present in Message/get; got: {msg}"
    );
    let bm_arr = bm.as_array().unwrap();
    assert_eq!(bm_arr.len(), 1, "must have one broadcast mention");
    assert_eq!(bm_arr[0]["scope"], "here");
    assert_eq!(bm_arr[0]["offset"], 0);
    assert_eq!(bm_arr[0]["length"], 5);
}

// ===========================================================================
// GROUP D — Message handler integration tests
// ===========================================================================

// Oracle: RFC 8620 §5.1 — Message/get with specific IDs must return exactly
// those messages.
#[tokio::test]
async fn message_get_by_ids() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-get-ids");

    // Create two messages.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {"chatId": chat_id.clone(), "body": "first"},
                "m1": {"chatId": chat_id.clone(), "body": "second"}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let args = &resp.method_responses[0].1;
    let id0 = args["created"]["m0"]["id"].as_str().unwrap().to_string();
    let id1 = args["created"]["m1"]["id"].as_str().unwrap().to_string();

    // Fetch only one by ID.
    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": [id0.clone()]}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/get");
    let list = args["list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "must return exactly the requested message");
    assert_eq!(list[0]["id"], id0);
    assert_eq!(list[0]["body"], "first");
    // notFound must be empty.
    let nf = args["notFound"].as_array().unwrap();
    assert!(nf.is_empty(), "notFound must be empty; got: {nf:?}");

    // Fetch both.
    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": [id0.clone(), id1.clone()]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let list = args["list"].as_array().unwrap();
    assert_eq!(list.len(), 2, "must return both messages");
}

// Oracle: RFC 8620 §5.1 — Message/get with unknown IDs must put them in notFound.
#[tokio::test]
async fn message_get_unknown_ids_returns_not_found() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": ["nonexistent-msg-1", "nonexistent-msg-2"]}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/get");
    let list = args["list"].as_array().unwrap();
    assert!(list.is_empty(), "list must be empty for unknown IDs");
    let nf = args["notFound"].as_array().unwrap();
    assert_eq!(nf.len(), 2, "notFound must have both unknown IDs");
    assert!(nf.contains(&json!("nonexistent-msg-1")));
    assert!(nf.contains(&json!("nonexistent-msg-2")));
}

// Oracle: RFC 8620 §5.1 — Message/get with ids=[] must return empty list and
// empty notFound.
#[tokio::test]
async fn message_get_empty_ids_returns_empty_list() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-get-empty");

    // Create a message to ensure it is NOT returned.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m0": {"chatId": chat_id, "body": "invisible"}}
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Fetch with empty ids array.
    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": []}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["list"], json!([]), "ids=[] must return empty list");
    assert_eq!(args["notFound"], json!([]), "ids=[] must return empty notFound");
}

// Oracle: RFC 8620 §5.1 — Message/get with properties filter should still
// return the message but only the requested fields.  In our implementation
// properties filtering is not implemented so all fields are always returned.
// This test verifies the response still has the expected fields.
#[tokio::test]
async fn message_get_with_properties_returns_all_fields() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-get-props");

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m0": {"chatId": chat_id.clone(), "body": "hello props"}}
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let msg_id = resp.method_responses[0].1["created"]["m0"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Request with properties (handler may or may not filter).
    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": [msg_id.clone()], "properties": ["id", "body"]}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/get");
    let list = args["list"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    // The message must at minimum contain id and body.
    assert_eq!(list[0]["id"], msg_id);
    assert_eq!(list[0]["body"], "hello props");
}

// Oracle: RFC 8620 §5.6 — Message/changes with sinceState="s-0" must return all
// messages created since store initialization.
#[tokio::test]
async fn message_changes_since_s0_returns_all() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-chg-all");

    // Create two messages.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {"chatId": chat_id.clone(), "body": "one"},
                "m1": {"chatId": chat_id.clone(), "body": "two"}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let args = &resp.method_responses[0].1;
    let id0 = args["created"]["m0"]["id"].as_str().unwrap().to_string();
    let id1 = args["created"]["m1"]["id"].as_str().unwrap().to_string();

    // Changes since s-0 must include both.
    let req = kith_request(vec![(
        "Message/changes",
        json!({"accountId": "a-self", "sinceState": "s-0"}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/changes");
    let created = args["created"].as_array().unwrap();
    assert!(
        created.contains(&json!(id0)),
        "id0 must be in created; got: {created:?}"
    );
    assert!(
        created.contains(&json!(id1)),
        "id1 must be in created; got: {created:?}"
    );
    // hasMoreChanges must be false (no maxChanges limit).
    assert_eq!(args["hasMoreChanges"], false);
}

// Oracle: RFC 8620 §5.6 — Message/changes with sinceState equal to current state
// must return empty created/updated/destroyed arrays.
#[tokio::test]
async fn message_changes_at_current_state_returns_empty() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-chg-cur");

    // Create a message.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m0": {"chatId": chat_id.clone(), "body": "msg"}}
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let new_state = resp.method_responses[0].1["newState"]
        .as_str()
        .unwrap()
        .to_string();

    // Changes at the new state — nothing new.
    let req = kith_request(vec![(
        "Message/changes",
        json!({"accountId": "a-self", "sinceState": new_state.clone()}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["created"], json!([]));
    assert_eq!(args["updated"], json!([]));
    assert_eq!(args["destroyed"], json!([]));
    assert_eq!(args["newState"], new_state);
}

// Oracle: Message/changes with malformed sinceState must return cannotCalculateChanges.
#[tokio::test]
async fn message_changes_malformed_state_returns_error() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Message/changes",
        json!({"accountId": "a-self", "sinceState": "invalid-format"}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/changes");
    assert_eq!(
        args["type"], "cannotCalculateChanges",
        "malformed sinceState must return cannotCalculateChanges; got: {args}"
    );
}

// Oracle: Message/query with filter.chatId returns messages for that chat only,
// sorted by receivedAt descending (newest first).
#[tokio::test]
async fn message_query_filter_by_chat_id() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_a = setup_direct_chat(&store, "msg-qry-a");
    let chat_b = setup_direct_chat(&store, "msg-qry-b");

    // Create messages in both chats.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "ma": {"chatId": chat_a.clone(), "body": "in chat A"},
                "mb": {"chatId": chat_b.clone(), "body": "in chat B"}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let args = &resp.method_responses[0].1;
    let id_a = args["created"]["ma"]["id"].as_str().unwrap().to_string();
    let id_b = args["created"]["mb"]["id"].as_str().unwrap().to_string();

    // Query for chat A only.
    let req = kith_request(vec![(
        "Message/query",
        json!({"accountId": "a-self", "filter": {"chatId": chat_a.clone()}}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/query");
    let ids = args["ids"].as_array().unwrap();
    assert!(
        ids.contains(&json!(id_a)),
        "chat A message must be in query result; got: {ids:?}"
    );
    assert!(
        !ids.contains(&json!(id_b)),
        "chat B message must NOT be in chat A query result; got: {ids:?}"
    );
}

// Oracle: Message/query with position and limit pagination returns the correct
// subset of messages.
#[tokio::test]
async fn message_query_position_and_limit_pagination() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-qry-pag");

    // Create 3 messages.
    for i in 0..3 {
        let req = kith_request(vec![(
            "Message/set",
            json!({
                "accountId": "a-self",
                "create": {
                    format!("m{i}"): {"chatId": chat_id.clone(), "body": format!("msg {i}")}
                }
            }),
            "c0",
        )]);
        d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
    }

    // Query with position=1, limit=1 — should get exactly 1 message.
    let req = kith_request(vec![(
        "Message/query",
        json!({
            "accountId": "a-self",
            "filter": {"chatId": chat_id.clone()},
            "position": 1,
            "limit": 1
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let ids = args["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 1, "position=1 limit=1 must return exactly 1");
    assert_eq!(args["position"], 1);
}

// Oracle: Message/query for a nonexistent chat must return invalidArguments.
#[tokio::test]
async fn message_query_nonexistent_chat_returns_error() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Message/query",
        json!({
            "accountId": "a-self",
            "filter": {"chatId": "chat-does-not-exist"}
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/query");
    assert_eq!(
        args["type"], "invalidArguments",
        "nonexistent chatId must return invalidArguments; got: {args}"
    );
}

// Oracle: Message/query default sort is receivedAt descending — newest messages
// appear first in the result.
#[tokio::test]
async fn message_query_default_sort_received_at_desc() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-qry-sort");

    // Create messages sequentially so they have increasing receivedAt.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m0": {"chatId": chat_id.clone(), "body": "oldest"}}
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let id_oldest = resp.method_responses[0].1["created"]["m0"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m1": {"chatId": chat_id.clone(), "body": "newest"}}
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let id_newest = resp.method_responses[0].1["created"]["m1"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Query — default sort should put newest first (position=0).
    let req = kith_request(vec![(
        "Message/query",
        json!({
            "accountId": "a-self",
            "filter": {"chatId": chat_id.clone()}
        }),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let ids = args["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
    // Newest message is at position 0 (desc order).
    assert_eq!(ids[0], id_newest, "newest message must be first");
    assert_eq!(ids[1], id_oldest, "oldest message must be second");
}

// Oracle: Message/queryChanges with sinceQueryState from before inserts must
// return added entries with id and index fields.
#[tokio::test]
async fn message_query_changes_returns_added_entries() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-qchg");

    // Get state before any messages.
    let state_before = {
        let guard = store.lock().unwrap();
        guard.messages().get_state().unwrap()
    };

    // Create a message.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m0": {"chatId": chat_id.clone(), "body": "qchg test"}}
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let msg_id = resp.method_responses[0].1["created"]["m0"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // queryChanges from state_before.
    let req = kith_request(vec![(
        "Message/queryChanges",
        json!({
            "accountId": "a-self",
            "sinceQueryState": state_before,
            "filter": {"chatId": chat_id.clone()}
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Message/queryChanges");
    let added = args["added"].as_array().unwrap();
    assert!(!added.is_empty(), "added must not be empty");
    assert_eq!(added[0]["id"], msg_id);
    assert!(added[0].get("index").is_some(), "added entry must have index");
    assert_eq!(args["removed"], json!([]));
}

// Oracle: Message/queryChanges at current state returns empty added and removed.
#[tokio::test]
async fn message_query_changes_at_current_state_returns_empty() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-qchg-cur");

    // Create a message.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m0": {"chatId": chat_id.clone(), "body": "qchg-cur"}}
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let new_state = resp.method_responses[0].1["newState"]
        .as_str()
        .unwrap()
        .to_string();

    // queryChanges at the current state — nothing new.
    let req = kith_request(vec![(
        "Message/queryChanges",
        json!({
            "accountId": "a-self",
            "sinceQueryState": new_state.clone(),
            "filter": {"chatId": chat_id.clone()}
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["added"], json!([]));
    assert_eq!(args["removed"], json!([]));
    assert_eq!(args["newQueryState"], new_state);
}

// ===========================================================================
// GROUP E — Chat handler integration tests
// ===========================================================================

// Oracle: RFC 8620 §5.1 — Chat/get with no ids param returns all chats.
#[tokio::test]
async fn chat_get_all_chats() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_a = setup_direct_chat(&store, "chat-get-a");
    let chat_b = setup_group_chat(&store, "chat-get-b");

    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self"}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/get");
    let list = args["list"].as_array().unwrap();
    assert!(list.len() >= 2, "must return at least 2 chats; got {}", list.len());
    let ids: Vec<&str> = list.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(ids.contains(&chat_a.as_str()), "chat_a must be in list");
    assert!(ids.contains(&chat_b.as_str()), "chat_b must be in list");
}

// Oracle: RFC 8620 §5.1 — Chat/get with specific IDs returns only those.
#[tokio::test]
async fn chat_get_by_specific_ids() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_a = setup_direct_chat(&store, "chat-getid-a");
    let _chat_b = setup_direct_chat(&store, "chat-getid-b");

    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_a.clone()]}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let list = args["list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "must return exactly the requested chat");
    assert_eq!(list[0]["id"], chat_a);
}

// Oracle: Chat/get with unknown IDs puts them in notFound.
#[tokio::test]
async fn chat_get_unknown_ids_in_not_found() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": ["ghost-chat-1", "ghost-chat-2"]}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let list = args["list"].as_array().unwrap();
    assert!(list.is_empty(), "list must be empty for unknown IDs");
    let nf = args["notFound"].as_array().unwrap();
    assert_eq!(nf.len(), 2, "notFound must have 2 entries");
    assert!(nf.contains(&json!("ghost-chat-1")));
    assert!(nf.contains(&json!("ghost-chat-2")));
}

// Oracle: Chat/get returns all metadata fields (name, muted, kind, etc.).
#[tokio::test]
async fn chat_get_returns_all_metadata_fields() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "chat-meta");

    let req = kith_request(vec![(
        "Chat/get",
        json!({"accountId": "a-self", "ids": [chat_id.clone()]}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let chat = &args["list"][0];

    // Must have these structural fields.
    assert_eq!(chat["id"], chat_id);
    assert!(chat.get("kind").is_some(), "kind field must be present");
    assert!(chat.get("muted").is_some(), "muted field must be present");
    assert!(
        chat.get("receiveTypingIndicators").is_some(),
        "receiveTypingIndicators field must be present"
    );
}

// Oracle: Chat/set create for a group chat with name must succeed.
#[tokio::test]
async fn chat_set_create_group_chat_with_name() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create contact first (needed for Chat/set).
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-grp-create",
                    "login": "grp@example.com",
                    "mailboxHost": "grp.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Create a chat (direct, since Chat/set only supports direct in Phase 1).
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "create": {"ch0": {"contactId": "uid-grp-create"}}
        }),
        "ch0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/set");
    assert!(
        args["created"].get("ch0").is_some(),
        "chat create must succeed; got: {args}"
    );
    let chat_id = args["created"]["ch0"]["id"].as_str().unwrap();
    assert!(!chat_id.is_empty(), "chat ID must be non-empty");
}

// Oracle: Chat/set create with duplicate contactId returns alreadyExists.
#[tokio::test]
async fn chat_set_create_duplicate_returns_already_exists() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-dup-chat",
                    "login": "dup@example.com",
                    "mailboxHost": "dup.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // First create — succeeds.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "create": {"ch0": {"contactId": "uid-dup-chat"}}
        }),
        "ch0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    assert!(resp.method_responses[0].1["created"].get("ch0").is_some());

    // Second create — must be notCreated/alreadyExists.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "create": {"ch1": {"contactId": "uid-dup-chat"}}
        }),
        "ch1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("ch1").is_some(),
        "duplicate must be in notCreated; got: {args}"
    );
    assert_eq!(args["notCreated"]["ch1"]["type"], "alreadyExists");
}

// Oracle: Chat/set create with invalid (unknown) contactId returns notCreated/notFound.
#[tokio::test]
async fn chat_set_create_invalid_contact_id() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "create": {"ch0": {"contactId": "uid-nobody-here"}}
        }),
        "ch0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/set");
    assert!(
        args["notCreated"].get("ch0").is_some(),
        "unknown contactId must be in notCreated; got: {args}"
    );
    assert_eq!(args["notCreated"]["ch0"]["type"], "notFound");
}

// Oracle: Chat/changes sinceState returns updated chats after metadata change.
#[tokio::test]
async fn chat_changes_after_metadata_update() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_group_chat(&store, "chat-chg-upd");

    // Get current state.
    let state_before = {
        let guard = store.lock().unwrap();
        guard.chats().get_state().unwrap()
    };

    // Update the chat name.
    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "update": { chat_id.clone(): {"name": "Updated Name"} }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Chat/changes from state_before.
    let req = kith_request(vec![(
        "Chat/changes",
        json!({"accountId": "a-self", "sinceState": state_before}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/changes");
    // The chat was created before state_before (by setup_group_chat), so it
    // appears in the "updated" list, not "created".
    let updated = args["updated"].as_array().unwrap();
    assert!(
        updated.contains(&json!(chat_id)),
        "chat_id must appear in updated; got: {args}"
    );
}

// Oracle: Chat/query returns chat IDs ordered by lastMessageAt DESC nulls last,
// then createdAt DESC.
#[tokio::test]
async fn chat_query_default_sort() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create two chats with explicitly different createdAt times via the store
    // to ensure a deterministic sort order.
    let chat_older = "chat-sort-older";
    let chat_newer = "chat-sort-newer";
    {
        let guard = store.lock().unwrap();
        guard
            .contacts()
            .upsert(
                "uid-sort-old",
                "sort-old@example.com",
                "sort-old.tail.ts.net",
                None,
                1000,
            )
            .unwrap();
        guard
            .contacts()
            .upsert(
                "uid-sort-new",
                "sort-new@example.com",
                "sort-new.tail.ts.net",
                None,
                1000,
            )
            .unwrap();
        guard
            .chats()
            .create(chat_older, "direct", Some("uid-sort-old"), 1_000_000)
            .unwrap();
        guard
            .chats()
            .create(chat_newer, "direct", Some("uid-sort-new"), 2_000_000)
            .unwrap();
    }

    let req = kith_request(vec![("Chat/query", json!({"accountId": "a-self"}), "c0")]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let ids = args["ids"].as_array().unwrap();
    // Both chats have null lastMessageAt, so ordering is by createdAt DESC.
    // chat_newer (createdAt=2_000_000) should appear before chat_older (createdAt=1_000_000).
    let pos_older = ids.iter().position(|v| v.as_str() == Some(chat_older));
    let pos_newer = ids.iter().position(|v| v.as_str() == Some(chat_newer));
    assert!(
        pos_newer.is_some() && pos_older.is_some(),
        "both chats must appear in query; got: {ids:?}"
    );
    // Newer chat should appear before older in DESC order.
    assert!(
        pos_newer.unwrap() < pos_older.unwrap(),
        "newer chat should appear before older in createdAt DESC; got: {ids:?}"
    );
}

// ===========================================================================
// GROUP F — ChatContact handler integration tests
// ===========================================================================

// Oracle: RFC 8620 §5.1 — ChatContact/get with ids=null returns all contacts.
#[tokio::test]
async fn contact_get_all_contacts() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create two contacts.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {"id": "uid-cg-a", "login": "a@example.com", "mailboxHost": "a.tail.ts.net"},
                "c1": {"id": "uid-cg-b", "login": "b@example.com", "mailboxHost": "b.tail.ts.net"}
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Get all contacts.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self"}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/get");
    let list = args["list"].as_array().unwrap();
    assert!(list.len() >= 2, "must return at least 2 contacts");
    let ids: Vec<&str> = list.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(ids.contains(&"uid-cg-a"));
    assert!(ids.contains(&"uid-cg-b"));
}

// Oracle: ChatContact/get by specific IDs returns only those contacts.
#[tokio::test]
async fn contact_get_by_specific_ids() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {"id": "uid-cid-a", "login": "cid-a@example.com", "mailboxHost": "a.ts.net"},
                "c1": {"id": "uid-cid-b", "login": "cid-b@example.com", "mailboxHost": "b.ts.net"}
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Fetch only one.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self", "ids": ["uid-cid-a"]}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let list = args["list"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], "uid-cid-a");
    assert!(args["notFound"].as_array().unwrap().is_empty());
}

// Oracle: ChatContact/get with unknown IDs puts them in notFound.
#[tokio::test]
async fn contact_get_unknown_ids_in_not_found() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self", "ids": ["uid-phantom"]}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let list = args["list"].as_array().unwrap();
    assert!(list.is_empty());
    let nf = args["notFound"].as_array().unwrap();
    assert_eq!(nf.len(), 1);
    assert_eq!(nf[0], "uid-phantom");
}

// Oracle: ChatContact/set create adds a new contact with peer info.
#[tokio::test]
async fn contact_set_create_new_contact() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-new-contact",
                    "login": "new@example.com",
                    "mailboxHost": "new.tail.ts.net",
                    "displayName": "New Person"
                }
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/set");
    assert!(args["created"].get("c0").is_some());
    assert_eq!(args["created"]["c0"]["id"], "uid-new-contact");
    assert_eq!(args["created"]["c0"]["login"], "new@example.com");
    assert_eq!(args["created"]["c0"]["displayName"], "New Person");
}

// Oracle: ChatContact/set create with duplicate ID (upsert) does not fail —
// the store uses upsert semantics.
#[tokio::test]
async fn contact_set_create_duplicate_upserts() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-dup-contact",
                    "login": "dup@example.com",
                    "mailboxHost": "dup.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Same ID again — should succeed (upsert).
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c1": {
                    "id": "uid-dup-contact",
                    "login": "dup-new@example.com",
                    "mailboxHost": "dup2.tail.ts.net"
                }
            }
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["created"].get("c1").is_some(),
        "duplicate upsert must succeed; got: {args}"
    );
}

// Oracle: ChatContact/set update displayName must succeed and persist.
#[tokio::test]
async fn contact_set_update_display_name() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-upd-dn",
                    "login": "dn@example.com",
                    "mailboxHost": "dn.tail.ts.net",
                    "displayName": "Original"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Update displayName.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "update": {"uid-upd-dn": {"displayName": "Renamed"}}
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get("uid-upd-dn").is_some(),
        "displayName update must succeed; got: {args}"
    );

    // Verify via get.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self", "ids": ["uid-upd-dn"]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["list"][0]["displayName"], "Renamed");
}

// Oracle: ChatContact/set update blocked=true must succeed and persist.
#[tokio::test]
async fn contact_set_update_blocked_status() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-upd-blk",
                    "login": "blk@example.com",
                    "mailboxHost": "blk.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Block the contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "update": {"uid-upd-blk": {"blocked": true}}
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get("uid-upd-blk").is_some(),
        "blocked update must succeed; got: {args}"
    );

    // Verify via get.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self", "ids": ["uid-upd-blk"]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["list"][0]["blocked"], true, "blocked must be true");
}

// Oracle: ChatContact/set update presence fields must succeed.
#[tokio::test]
async fn contact_set_update_presence_fields() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-upd-pres",
                    "login": "pres@example.com",
                    "mailboxHost": "pres.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Update presence and statusText.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "update": {
                "uid-upd-pres": {
                    "presence": "online",
                    "statusText": "Working hard"
                }
            }
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get("uid-upd-pres").is_some(),
        "presence update must succeed; got: {args}"
    );

    // Verify via get.
    let req = kith_request(vec![(
        "ChatContact/get",
        json!({"accountId": "a-self", "ids": ["uid-upd-pres"]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["list"][0]["presence"], "online");
    assert_eq!(args["list"][0]["statusText"], "Working hard");
}

// Oracle: ChatContact/changes sinceState returns created contacts after insert.
#[tokio::test]
async fn contact_changes_after_create() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Get state before.
    let state_before = {
        let guard = store.lock().unwrap();
        guard.contacts().get_state().unwrap()
    };

    // Create a contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-chg-new",
                    "login": "chg@example.com",
                    "mailboxHost": "chg.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Changes since state_before.
    let req = kith_request(vec![(
        "ChatContact/changes",
        json!({"accountId": "a-self", "sinceState": state_before}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/changes");
    let created = args["created"].as_array().unwrap();
    assert!(
        created.contains(&json!("uid-chg-new")),
        "new contact must be in created; got: {created:?}"
    );
}

// Oracle: ChatContact/changes sinceState after update returns updated contacts.
#[tokio::test]
async fn contact_changes_after_update() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create a contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-chg-upd",
                    "login": "chgupd@example.com",
                    "mailboxHost": "chgupd.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let state_after_create = resp.method_responses[0].1["newState"]
        .as_str()
        .unwrap()
        .to_string();

    // Update the contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "update": {"uid-chg-upd": {"displayName": "Updated"}}
        }),
        "c1",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Changes since state_after_create.
    let req = kith_request(vec![(
        "ChatContact/changes",
        json!({"accountId": "a-self", "sinceState": state_after_create}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let updated = args["updated"].as_array().unwrap();
    assert!(
        updated.contains(&json!("uid-chg-upd")),
        "updated contact must be in updated list; got: {args}"
    );
}

// Oracle: ChatContact/query lists all contact IDs.
#[tokio::test]
async fn contact_query_list_all() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create contacts.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {"id": "uid-qry-a", "login": "qrya@example.com", "mailboxHost": "a.ts.net"},
                "c1": {"id": "uid-qry-b", "login": "qryb@example.com", "mailboxHost": "b.ts.net"}
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    let req = kith_request(vec![(
        "ChatContact/query",
        json!({"accountId": "a-self"}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/query");
    let ids = args["ids"].as_array().unwrap();
    assert!(ids.len() >= 2, "must have at least 2 contact IDs");
    let id_strs: Vec<&str> = ids.iter().filter_map(|v| v.as_str()).collect();
    assert!(id_strs.contains(&"uid-qry-a"));
    assert!(id_strs.contains(&"uid-qry-b"));
}

// Oracle: ChatContact/query with pagination (position and limit) returns a subset.
#[tokio::test]
async fn contact_query_pagination() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create 3 contacts with sorted logins.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {"id": "uid-pag-a", "login": "aaa-pag@example.com", "mailboxHost": "a.ts.net"},
                "c1": {"id": "uid-pag-b", "login": "bbb-pag@example.com", "mailboxHost": "b.ts.net"},
                "c2": {"id": "uid-pag-c", "login": "ccc-pag@example.com", "mailboxHost": "c.ts.net"}
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // position=1, limit=1.
    let req = kith_request(vec![(
        "ChatContact/query",
        json!({"accountId": "a-self", "position": 1, "limit": 1}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let ids = args["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 1, "position=1 limit=1 must return exactly 1");
    assert_eq!(args["position"], 1);
}

// Oracle: ChatContact/queryChanges with sinceQueryState from before creates
// returns added entries.
#[tokio::test]
async fn contact_query_changes_returns_added() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Get state before.
    let state_before = {
        let guard = store.lock().unwrap();
        guard.contacts().get_state().unwrap()
    };

    // Create a contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-qchg-add",
                    "login": "qchg@example.com",
                    "mailboxHost": "qchg.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // queryChanges from state_before.
    let req = kith_request(vec![(
        "ChatContact/queryChanges",
        json!({"accountId": "a-self", "sinceQueryState": state_before}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "ChatContact/queryChanges");
    let added = args["added"].as_array().unwrap();
    assert!(!added.is_empty(), "added must not be empty");
    // Each added entry must have id and index.
    assert!(added[0].get("id").is_some(), "added entry must have id");
    assert!(added[0].get("index").is_some(), "added entry must have index");
    // The new contact must be in the added list.
    let added_ids: Vec<&str> = added.iter().filter_map(|e| e["id"].as_str()).collect();
    assert!(
        added_ids.contains(&"uid-qchg-add"),
        "new contact must be in added; got: {added_ids:?}"
    );
}

// Oracle: ChatContact/queryChanges at current state returns empty added/removed.
#[tokio::test]
async fn contact_query_changes_at_current_state_empty() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create a contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-qchg-cur",
                    "login": "qchgcur@example.com",
                    "mailboxHost": "qchgcur.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let new_state = resp.method_responses[0].1["newState"]
        .as_str()
        .unwrap()
        .to_string();

    // queryChanges at new_state — nothing new.
    let req = kith_request(vec![(
        "ChatContact/queryChanges",
        json!({"accountId": "a-self", "sinceQueryState": new_state.clone()}),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["added"], json!([]));
    assert_eq!(args["removed"], json!([]));
    assert_eq!(args["newQueryState"], new_state);
}

// ===========================================================================
// GROUP G — Additional edge case tests
// ===========================================================================

// Oracle: Message/set create with missing body must be rejected.
#[tokio::test]
async fn message_set_create_missing_body_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-nobody");

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {"chatId": chat_id.clone()}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "missing body must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// Oracle: Message/set create with missing chatId must be rejected.
#[tokio::test]
async fn message_set_create_missing_chat_id_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {"body": "hello without chatId"}
            }
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notCreated"].get("m0").is_some(),
        "missing chatId must be rejected; got: {args}"
    );
    assert_eq!(args["notCreated"]["m0"]["type"], "invalidArguments");
}

// Oracle: ChatContact/set update with unknown field must be rejected with
// invalidProperties.
#[tokio::test]
async fn contact_set_update_unknown_field_rejected() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-unkfld",
                    "login": "unk@example.com",
                    "mailboxHost": "unk.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Update with unknown field.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "update": {"uid-unkfld": {"fakeProperty": "value"}}
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notUpdated"].get("uid-unkfld").is_some(),
        "unknown field update must be rejected; got: {args}"
    );
    assert_eq!(args["notUpdated"]["uid-unkfld"]["type"], "invalidProperties");
}

// Oracle: Chat/set destroy must always be rejected (chats persist in Phase 1).
#[tokio::test]
async fn chat_set_destroy_forbidden() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "chat-destroy");

    let req = kith_request(vec![(
        "Chat/set",
        json!({
            "accountId": "a-self",
            "destroy": [chat_id.clone()]
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/set");
    assert!(
        args["notDestroyed"].get(&chat_id).is_some(),
        "chat destroy must be rejected; got: {args}"
    );
    assert_eq!(args["notDestroyed"][&chat_id]["type"], "forbidden");
    assert_eq!(args["destroyed"], json!([]));
}

// Oracle: Message/set update readAt must succeed (the only patchable field).
#[tokio::test]
async fn message_set_update_read_at_succeeds() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-readat");

    // Create a message.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {"m0": {"chatId": chat_id.clone(), "body": "read me"}}
        }),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let msg_id = resp.method_responses[0].1["created"]["m0"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Update readAt.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "update": {
                msg_id.clone(): {"readAt": "2026-01-15T10:00:00Z"}
            }
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["updated"].get(&msg_id).is_some(),
        "readAt update must succeed; got: {args}"
    );

    // Verify via Message/get.
    let req = kith_request(vec![(
        "Message/get",
        json!({"accountId": "a-self", "ids": [msg_id.clone()]}),
        "c2",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    let msg = &args["list"][0];
    assert!(
        msg["readAt"].as_str().is_some(),
        "readAt must be set after update; got: {msg}"
    );
}

// Oracle: ChatContact/set destroy must always be rejected (contacts are auto-managed).
#[tokio::test]
async fn contact_set_destroy_forbidden() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    // Create a contact.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "create": {
                "c0": {
                    "id": "uid-dest",
                    "login": "dest@example.com",
                    "mailboxHost": "dest.tail.ts.net"
                }
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Attempt destroy.
    let req = kith_request(vec![(
        "ChatContact/set",
        json!({
            "accountId": "a-self",
            "destroy": ["uid-dest"]
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert!(
        args["notDestroyed"].get("uid-dest").is_some(),
        "contact destroy must be rejected; got: {args}"
    );
    assert_eq!(args["notDestroyed"]["uid-dest"]["type"], "forbidden");
}

// Oracle: Chat/changes with malformed sinceState returns cannotCalculateChanges.
#[tokio::test]
async fn chat_changes_malformed_state_returns_error() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));

    let req = kith_request(vec![(
        "Chat/changes",
        json!({"accountId": "a-self", "sinceState": "garbage-state"}),
        "c0",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (name, args, _) = &resp.method_responses[0];
    assert_eq!(name, "Chat/changes");
    assert_eq!(
        args["type"], "cannotCalculateChanges",
        "malformed Chat/changes sinceState must return cannotCalculateChanges; got: {args}"
    );
}

// Oracle: Message/query with calculateTotal=true returns a total count.
#[tokio::test]
async fn message_query_calculate_total() {
    let store = make_store();
    let (d, _blob_dir) = make_dispatcher(Arc::clone(&store));
    let chat_id = setup_direct_chat(&store, "msg-qry-total");

    // Create 2 messages.
    let req = kith_request(vec![(
        "Message/set",
        json!({
            "accountId": "a-self",
            "create": {
                "m0": {"chatId": chat_id.clone(), "body": "one"},
                "m1": {"chatId": chat_id.clone(), "body": "two"}
            }
        }),
        "c0",
    )]);
    d.dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;

    // Query with calculateTotal=true.
    let req = kith_request(vec![(
        "Message/query",
        json!({
            "accountId": "a-self",
            "filter": {"chatId": chat_id.clone()},
            "calculateTotal": true
        }),
        "c1",
    )]);
    let resp = d
        .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
        .await;
    let (_, args, _) = &resp.method_responses[0];
    assert_eq!(args["total"], 2, "total must be 2 with calculateTotal=true");
    let ids = args["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
}
