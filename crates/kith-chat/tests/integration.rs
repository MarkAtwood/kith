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

fn make_dispatcher(store: Arc<Mutex<kith_store::Store>>) -> Dispatcher {
    let blob_store = Arc::new(kith_attach::BlobStore::new(std::env::temp_dir()));
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
    d
}

fn kith_request(method_calls: Vec<(&str, serde_json::Value, &str)>) -> JmapRequest {
    JmapRequest {
        using: vec![
            "urn:ietf:params:jmap:core".to_string(),
            "urn:ietf:params:jmap:chat".to_string(),
        ],
        method_calls: method_calls
            .into_iter()
            .map(|(m, a, c)| (m.to_string(), a, c.to_string()))
            .collect(),
    }
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
    let d = make_dispatcher(Arc::clone(&store));

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
    let d = make_dispatcher(Arc::clone(&store));

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
    let d = make_dispatcher(Arc::clone(&store));

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

// Oracle: RFC 8620 §7.1 — forbiddenMethod is returned when the caller's
// role does not satisfy the method's required role.
// These tests use the Dispatcher directly (not the handlers) so they test
// the actual role gate, not a bypass.
//
// All 10 owner methods must reject when called with Role::Peer.
// The dispatcher emits the error in the method_responses tuple —
// HTTP 200 body with type="forbiddenMethod" (RFC 8620 §3.4).
#[tokio::test]
async fn test_peer_cannot_call_owner_methods() {
    let store = make_store();
    let d = make_dispatcher(Arc::clone(&store));

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
        // Oracle: RFC 8620 §7.1 — type must be "forbiddenMethod".
        assert_eq!(
            args["type"], "forbiddenMethod",
            "Role::Peer calling {method} must return forbiddenMethod; got: {args}"
        );
    }
}

// Oracle: RFC 8620 §7.1 — unknownMethod is returned for a method name not
// in the METHOD_ROLES registry.
#[tokio::test]
async fn test_owner_cannot_call_unknown_method() {
    let store = make_store();
    let d = make_dispatcher(Arc::clone(&store));

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

// Oracle: Role::Owner calling a Peer-only method must return forbiddenMethod.
// Peer/deliver and Peer/receipt are in METHOD_ROLES as Role::Peer.
#[tokio::test]
async fn test_owner_cannot_call_peer_methods() {
    let store = make_store();
    let d = make_dispatcher(Arc::clone(&store));

    for method in ["Peer/deliver", "Peer/receipt"] {
        let req = kith_request(vec![(method, json!({}), "c0")]);
        let resp = d
            .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
            .await;
        let (_, args, _) = &resp.method_responses[0];
        assert_eq!(
            args["type"], "forbiddenMethod",
            "Role::Owner calling {method} must return forbiddenMethod; got: {args}"
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
    let d = make_dispatcher(Arc::clone(&store));

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
    let d = make_dispatcher(Arc::clone(&store));

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
    let d = make_dispatcher(Arc::clone(&store));

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
    let d = make_dispatcher(Arc::clone(&store));

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
    let d = make_dispatcher(Arc::clone(&store));

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
    let d = make_dispatcher(Arc::clone(&store));

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
