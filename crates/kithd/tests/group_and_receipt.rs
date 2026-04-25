//! Integration tests for group-chat fanout and read-receipt round-trip.
//!
//! These tests require the `test-utils` feature:
//! ```sh
//! cargo test -p kithd --features test-utils
//! ```

// Pull in spawn_test_pair and its companions from harness.rs.
// This must be at the crate root (outside any mod block) to be visible.
#[cfg(feature = "test-utils")]
#[path = "harness.rs"]
mod harness;

#[cfg(feature = "test-utils")]
mod inner {
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use kith_core::AuthError;
    use kith_events::make_channel;
    use kith_store::Store;
    use kith_tslocal::{UserProfile, WhoIsNode, WhoIsResponse};
    use kithd::auth::WhoIsProvider;
    use kithd::build_app;
    use kithd::build_dispatcher;
    use kithd::extractors::AppState;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    // -----------------------------------------------------------------------
    // Test constants
    // -----------------------------------------------------------------------

    const ALICE_OWNER_ID: &str = "uid-alice";
    const ALICE_LOGIN: &str = "alice@example.com";
    const BOB_OWNER_ID: &str = "uid-bob";
    const BOB_LOGIN: &str = "bob@example.com";
    const CAROL_OWNER_ID: &str = "uid-carol";
    const CAROL_LOGIN: &str = "carol@example.com";

    /// Fixed socket address for alice's in-process owner calls.
    const ALICE_MOCK_ADDR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        10011,
    );

    /// Fixed socket address used when bob delivers a receipt to alice's peer inbox.
    const BOB_PEER_MOCK_ADDR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        10013,
    );

    /// 1:1 alice↔bob chat ID — sha256("uid-alice\x00uid-bob").
    /// Validated by the chat_id_matches_expected_constant test in harness.rs.
    const EXPECTED_1V1_CHAT_ID: &str =
        "d4f2c256272c172cb98fb77fd336bb46e22dc9976d03861fe8fc46c774c03eb0";

    /// Group chat ID for alice+bob+carol.
    /// Independent oracle: printf 'uid-alice\x00uid-bob\x00uid-carol' | sha256sum
    /// = c5bd75e387701b7bfb4af05c579338f66490bf8cd9916b9dcc1cacb4128549dd
    const EXPECTED_GROUP_CHAT_ID: &str =
        "c5bd75e387701b7bfb4af05c579338f66490bf8cd9916b9dcc1cacb4128549dd";

    // -----------------------------------------------------------------------
    // Test double: MockWhoIs — always returns the same identity.
    // -----------------------------------------------------------------------

    pub struct MockWhoIs(pub WhoIsResponse);

    impl WhoIsProvider for MockWhoIs {
        fn whois(
            &self,
            _addr: SocketAddr,
        ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send {
            let result = Ok(self.0.clone());
            async move { result }
        }
    }

    pub fn make_whois(id: &str, login: &str) -> WhoIsResponse {
        WhoIsResponse {
            node: WhoIsNode {
                name: format!("{id}-kith.tail12345.ts.net"),
            },
            user_profile: UserProfile {
                id: id.into(),
                login_name: login.into(),
                display_name: None,
            },
        }
    }

    fn make_blob_store() -> Arc<kith_attach::BlobStore> {
        let dir = std::env::temp_dir().join(format!(
            "kithd-test-blobs-gr-{}",
            kith_attach::BlobStore::generate_blob_id()
        ));
        let store = Arc::new(kith_attach::BlobStore::new(&dir));
        store.init().expect("blob store init must succeed");
        store
    }

    // -----------------------------------------------------------------------
    // Task B: read_receipt_round_trip
    //
    // Scenario:
    //   1. Alice creates a message in the 1:1 chat with bob.
    //   2. outbox_tick delivers it to bob's TLS listener.
    //   3. Bob marks the message as read via Message/set update (readAt).
    //   4. Bob's outbox gains a receipt row (kind='receipt') targeting alice.
    //   5. The receipt is posted directly to alice's peer-inbox router.
    //      This is a separate in-process router that shares alice's store and
    //      dispatcher, but uses bob's identity in MockWhoIs so the Caller
    //      extractor grants Role::Peer to the call.  This tests ReceiptHandler
    //      end-to-end without requiring a second TLS listener for alice.
    //   6. Alice's message now has read_at set.
    //
    // Independent oracles:
    //   - EXPECTED_BODY is a hardcoded literal, never derived from any code path.
    //   - Bob's outbox kind='receipt' is required by enqueue_receipt (kith-store spec).
    //   - After Peer/receipt, read_at is confirmed by reading the SQLite row
    //     directly — not through the JMAP response path.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn read_receipt_round_trip() {
        use kith_peer::{outbox_tick, PeerHttpClient};
        use std::time::{SystemTime, UNIX_EPOCH};

        const EXPECTED_BODY: &str = "hello, receipt test";

        // Step 1: spawn alice (in-process) + bob (TLS listener).
        // spawn_test_pair pre-populates alice↔bob contacts.
        let pair = super::harness::spawn_test_pair().await;

        // Step 2: update alice's contact for bob with the real loopback address.
        let bob_host = format!("127.0.0.1:{}", pair.bob_addr.port());
        pair.alice_store
            .lock()
            .expect("alice store lock must not be poisoned")
            .contacts()
            .upsert(BOB_OWNER_ID, BOB_LOGIN, &bob_host, None, 1_000_000)
            .expect("alice: update bob contact with real mailbox_host must succeed");

        // Step 3: create the alice↔bob chat in alice's store.
        let chat_id = EXPECTED_1V1_CHAT_ID;
        pair.alice_store
            .lock()
            .expect("alice store lock must not be poisoned")
            .chats()
            .create(chat_id, "direct", Some(BOB_OWNER_ID), 1_000_000)
            .expect("alice: create 1:1 chat must succeed");

        // Step 4: alice sends a message via her in-process router.
        // alice_router already has MockConnectInfo(ALICE_MOCK_ADDR) and alice's
        // identity → Owner classification.
        let request_body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [["Message/set", {
                "accountId": "a-self",
                "create": {
                    "m0": {
                        "chatId": chat_id,
                        "body": EXPECTED_BODY,
                        "bodyType": "text/plain"
                    }
                }
            }, "0"]]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&request_body)
                    .expect("request body serialization must not fail"),
            ))
            .expect("request construction must not fail");

        let resp = pair
            .alice_router
            .clone()
            .oneshot(req)
            .await
            .expect("alice router oneshot must not fail");

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "Message/set must return HTTP 200"
        );

        let resp_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("response body must be readable");
        let resp_json: serde_json::Value =
            serde_json::from_slice(&resp_bytes).expect("response must be valid JSON");

        let created = &resp_json["methodResponses"][0][1]["created"];
        assert!(
            created.get("m0").is_some(),
            "Message/set create must succeed; response: {resp_json}"
        );

        let msg_id = created["m0"]["id"]
            .as_str()
            .expect("created.m0.id must be a string")
            .to_string();

        // Step 5: deliver alice's message to bob via outbox_tick.
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let peer_client = PeerHttpClient::new_with_root_cert(&pair.bob_cert_der);
        outbox_tick(&pair.alice_store, &peer_client, ALICE_OWNER_ID, now_unix).await;

        // Oracle: bob must have the delivered message.
        // Capture bob_receiver_id (the receiver-assigned ULID) for use in the
        // Message/set update and outbox receipt lookup below.
        let bob_receiver_id = {
            let guard = pair
                .bob_store
                .lock()
                .expect("bob store lock must not be poisoned");
            let bob_msg = guard
                .messages()
                .find_by_sender_msg_id(chat_id, &msg_id)
                .expect("bob messages().find_by_sender_msg_id must not fail")
                .expect("bob must have the delivered message");
            assert_eq!(
                bob_msg.body, EXPECTED_BODY,
                "oracle: body on bob's side must match the hardcoded expected value"
            );
            assert_eq!(
                bob_msg.delivery_state,
                kith_core::DeliveryState::Received,
                "oracle: delivery_state must be Received after Peer/deliver"
            );
            assert_eq!(
                bob_msg.sender_id, ALICE_OWNER_ID,
                "oracle: sender_id on bob's side must be alice's user ID"
            );
            bob_msg.id.clone()
        };

        // Step 6: bob marks the message as read via Message/set update.
        // bob_router has MockConnectInfo(BOB_MOCK_ADDR) and MockWhoIs returning
        // bob → Owner classification.
        // "readAt" is a hardcoded RFC 3339 string — independent of any code path.
        let read_timestamp = "2026-01-01T12:00:00Z";
        let update_body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [["Message/set", {
                "accountId": "a-self",
                "update": {
                    bob_receiver_id.as_str(): { "readAt": read_timestamp }
                }
            }, "0"]]
        });

        let update_req = Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&update_body)
                    .expect("update body serialization must not fail"),
            ))
            .expect("update request construction must not fail");

        let update_resp = pair
            .bob_router
            .clone()
            .oneshot(update_req)
            .await
            .expect("bob router oneshot must not fail");

        assert_eq!(
            update_resp.status(),
            axum::http::StatusCode::OK,
            "Message/set update must return HTTP 200"
        );

        let update_bytes = axum::body::to_bytes(update_resp.into_body(), 1024 * 1024)
            .await
            .expect("update response body must be readable");
        let update_json: serde_json::Value =
            serde_json::from_slice(&update_bytes).expect("update response must be valid JSON");

        // Oracle: updated map must contain bob's receiver-assigned ID; notUpdated must not.
        assert!(
            update_json["methodResponses"][0][1]["updated"]
                .as_object()
                .map_or(false, |m| m.contains_key(&bob_receiver_id)),
            "Message/set update must succeed; response: {update_json}"
        );
        assert!(
            update_json["methodResponses"][0][1]["notUpdated"]
                .get(&bob_receiver_id)
                .is_none(),
            "notUpdated must not contain bob_receiver_id; response: {update_json}"
        );

        // Step 7: bob's outbox must have a receipt row targeting alice.
        // Oracle: enqueue_receipt creates kind='receipt' rows when a received
        // message (sender != "self") is marked as read and the sender is a
        // known, unblocked contact.
        {
            let guard = pair
                .bob_store
                .lock()
                .expect("bob store lock must not be poisoned");
            let entries = guard
                .outbox()
                .get_by_message(&bob_receiver_id)
                .expect("get_by_message must not fail on bob's store");
            assert!(
                !entries.is_empty(),
                "oracle: bob's outbox must have a receipt row after marking the message as read"
            );
            assert_eq!(
                entries[0].kind, "receipt",
                "oracle: outbox entry must have kind='receipt'"
            );
            assert_eq!(
                entries[0].peer_user_id, ALICE_OWNER_ID,
                "oracle: receipt outbox entry must target alice"
            );
        }

        // Step 8: deliver the receipt directly to alice's peer-inbox router.
        //
        // We build a dedicated alice peer-inbox router that shares alice's store
        // and dispatcher, but uses bob's identity in MockWhoIs.  The Caller
        // extractor will classify this connection as Role::Peer (bob is in
        // alice's contacts) and forward the Peer/receipt call to ReceiptHandler.
        // This simulates what outbox_tick would do on bob's side without
        // requiring a second TLS listener for alice.
        let alice_peer_whois = MockWhoIs(make_whois(BOB_OWNER_ID, BOB_LOGIN));
        let (alice_peer_events_tx, _alice_peer_events_rx) = make_channel(64);
        let alice_peer_blob_store = make_blob_store();
        let alice_peer_dispatcher = Arc::new(build_dispatcher(
            Arc::clone(&pair.alice_store),
            Arc::clone(&alice_peer_blob_store),
        ));
        let alice_peer_state = AppState {
            ts: Arc::new(alice_peer_whois),
            store: Arc::clone(&pair.alice_store),
            owner_id: ALICE_OWNER_ID.to_string(),
            owner_login: ALICE_LOGIN.to_string(),
            base_url: kithd::DEFAULT_BASE_URL.to_string(),
            events_tx: alice_peer_events_tx,
            dispatcher: alice_peer_dispatcher,
            blob_store: alice_peer_blob_store,
        };
        // BOB_PEER_MOCK_ADDR is distinct from ALICE_MOCK_ADDR; MockWhoIs ignores
        // the address and returns bob's identity regardless.
        let alice_peer_router =
            build_app(alice_peer_state).layer(MockConnectInfo(BOB_PEER_MOCK_ADDR));

        // Build the Peer/receipt request.
        // 'at' is a hardcoded RFC 3339 timestamp — independent oracle.
        let receipt_body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [["Peer/receipt", {
                "accountId": "a-self",
                "messageId": msg_id,
                "kind": "read",
                "at": read_timestamp
            }, "0"]]
        });

        let receipt_req = Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&receipt_body)
                    .expect("receipt body serialization must not fail"),
            ))
            .expect("receipt request construction must not fail");

        let receipt_resp = alice_peer_router
            .oneshot(receipt_req)
            .await
            .expect("alice peer router oneshot must not fail");

        assert_eq!(
            receipt_resp.status(),
            axum::http::StatusCode::OK,
            "Peer/receipt must return HTTP 200"
        );

        let receipt_bytes = axum::body::to_bytes(receipt_resp.into_body(), 1024 * 1024)
            .await
            .expect("receipt response body must be readable");
        let receipt_json: serde_json::Value =
            serde_json::from_slice(&receipt_bytes).expect("receipt response must be valid JSON");

        // Oracle: Peer/receipt handler returns {"accepted": true} on success.
        assert_eq!(
            receipt_json["methodResponses"][0][1]["accepted"].as_bool(),
            Some(true),
            "Peer/receipt must return accepted=true; response: {receipt_json}"
        );

        // Step 9: alice's message must now have read_at set.
        // Oracle: ReceiptHandler calls update_read_at which writes read_at to SQLite.
        // We read the message row directly — not through the JMAP response — to
        // verify the write actually occurred.
        {
            let guard = pair
                .alice_store
                .lock()
                .expect("alice store lock must not be poisoned");
            let alice_msg = guard
                .messages()
                .get(&msg_id)
                .expect("alice messages().get must not fail")
                .expect("alice must have the message");
            assert!(
                alice_msg.read_at.is_some(),
                "oracle: alice's message must have read_at set after Peer/receipt"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Task C (part 1): group_chat_message_enqueued_for_all_participants
    //
    // Verifies that when alice sends a message to a group chat with bob and
    // carol, the outbox contains exactly two rows — one per peer participant.
    //
    // This test depends on the composite PK (message_id, peer_user_id, kind)
    // in SCHEMA_V3 that allows multiple outbox rows per message.  With the
    // old single-column PK (message_id only), the second enqueue would fail
    // with a UNIQUE constraint violation and the second row would be silently
    // dropped.
    //
    // Independent oracles:
    //   - EXPECTED_GROUP_CHAT_ID was computed offline (printf ... | sha256sum).
    //   - Outbox row count = 2 is required by the group-fanout spec: one
    //     delivery per peer participant.
    //   - peer_user_id values are the hardcoded constants BOB_OWNER_ID and
    //     CAROL_OWNER_ID, not derived from any code path under test.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn group_chat_message_enqueued_for_all_participants() {
        // Step 1: set up alice's store with bob and carol as contacts.
        let alice_store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("alice in-memory store must open"),
        ));

        {
            let guard = alice_store
                .lock()
                .expect("alice store lock must not be poisoned");
            guard
                .contacts()
                .upsert(
                    BOB_OWNER_ID,
                    BOB_LOGIN,
                    "bob-kith.placeholder.ts.net",
                    None,
                    1_000_000,
                )
                .expect("alice: upsert bob as contact must succeed");
            guard
                .contacts()
                .upsert(
                    CAROL_OWNER_ID,
                    CAROL_LOGIN,
                    "carol-kith.placeholder.ts.net",
                    None,
                    1_000_000,
                )
                .expect("alice: upsert carol as contact must succeed");
        }

        // Step 2: build alice's in-process router.
        let alice_whois = MockWhoIs(make_whois(ALICE_OWNER_ID, ALICE_LOGIN));
        let (alice_events_tx, _alice_events_rx) = make_channel(64);
        let alice_blob_store = make_blob_store();
        let alice_dispatcher = Arc::new(build_dispatcher(
            Arc::clone(&alice_store),
            Arc::clone(&alice_blob_store),
        ));
        let alice_state = AppState {
            ts: Arc::new(alice_whois),
            store: Arc::clone(&alice_store),
            owner_id: ALICE_OWNER_ID.to_string(),
            owner_login: ALICE_LOGIN.to_string(),
            base_url: kithd::DEFAULT_BASE_URL.to_string(),
            events_tx: alice_events_tx,
            dispatcher: alice_dispatcher,
            blob_store: alice_blob_store,
        };
        let alice_router = build_app(alice_state).layer(MockConnectInfo(ALICE_MOCK_ADDR));

        // Step 3: create the group chat in alice's store and register members.
        let group_chat_id = EXPECTED_GROUP_CHAT_ID;
        {
            let guard = alice_store
                .lock()
                .expect("alice store lock must not be poisoned");
            let cs = guard.chats();
            cs.create(group_chat_id, "group", None, 1_000_000)
                .expect("alice: create group chat must succeed");
            cs.add_member(group_chat_id, BOB_OWNER_ID)
                .expect("alice: add bob to group chat must succeed");
            cs.add_member(group_chat_id, CAROL_OWNER_ID)
                .expect("alice: add carol to group chat must succeed");
        }

        // Step 4: alice sends a message to the group chat.
        const GROUP_MSG_BODY: &str = "hello group";
        let request_body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [["Message/set", {
                "accountId": "a-self",
                "create": {
                    "m0": {
                        "chatId": group_chat_id,
                        "body": GROUP_MSG_BODY,
                        "bodyType": "text/plain"
                    }
                }
            }, "0"]]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&request_body)
                    .expect("request body serialization must not fail"),
            ))
            .expect("request construction must not fail");

        let resp = alice_router
            .oneshot(req)
            .await
            .expect("alice router oneshot must not fail");

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "Message/set must return HTTP 200"
        );

        let resp_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("response body must be readable");
        let resp_json: serde_json::Value =
            serde_json::from_slice(&resp_bytes).expect("response must be valid JSON");

        let created = &resp_json["methodResponses"][0][1]["created"];
        assert!(
            created.get("m0").is_some(),
            "Message/set create must succeed; response: {resp_json}"
        );

        let msg_id = created["m0"]["id"]
            .as_str()
            .expect("created.m0.id must be a string")
            .to_string();

        // Step 5: check that alice's outbox has exactly two rows for this message.
        // Oracle: one row per peer participant (bob and carol).  If the old
        // single-column PK were still present, the second INSERT would be
        // silently ignored (ON CONFLICT DO NOTHING) or fail, giving count=1.
        {
            let guard = alice_store
                .lock()
                .expect("alice store lock must not be poisoned");
            let entries = guard
                .outbox()
                .get_by_message(&msg_id)
                .expect("get_by_message must not fail");

            assert_eq!(
                entries.len(),
                2,
                "oracle: outbox must have exactly 2 rows for a group message \
                 (one per peer participant); got {} rows",
                entries.len()
            );

            let mut peer_ids: Vec<&str> = entries.iter().map(|e| e.peer_user_id.as_str()).collect();
            peer_ids.sort_unstable();
            let mut expected_ids = [BOB_OWNER_ID, CAROL_OWNER_ID];
            expected_ids.sort_unstable();

            assert_eq!(
                peer_ids, expected_ids,
                "oracle: outbox rows must target bob and carol"
            );

            for entry in &entries {
                assert_eq!(
                    entry.kind, "message",
                    "oracle: group fanout outbox rows must have kind='message'"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Task C (part 2): group_chat_delivers_to_reachable_peer
    //
    // Verifies that in a group chat with a reachable peer (bob) and an
    // unreachable peer (carol), outbox_tick:
    //   - Delivers successfully to bob (outbox row deleted by complete_delivery).
    //   - Records a failure for carol (outbox row kept, attempt_count=1).
    //
    // Independent oracles:
    //   - delivery_state=Received on bob's side is mandated by Peer/deliver spec.
    //   - GROUP_DELIVERY_BODY is a hardcoded literal.
    //   - carol's attempt_count=1 is the value record_failure writes on the first
    //     failure — read directly from SQLite, not derived from the delivery path.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn group_chat_delivers_to_reachable_peer() {
        use kith_peer::{outbox_tick, PeerHttpClient};
        use std::time::{SystemTime, UNIX_EPOCH};

        const GROUP_DELIVERY_BODY: &str = "hello from alice to the group";

        // Step 1: spawn alice (in-process) + bob (TLS listener).
        let pair = super::harness::spawn_test_pair().await;

        // Step 2: update alice's contact for bob with the real loopback address.
        let bob_host = format!("127.0.0.1:{}", pair.bob_addr.port());
        pair.alice_store
            .lock()
            .expect("alice store lock must not be poisoned")
            .contacts()
            .upsert(BOB_OWNER_ID, BOB_LOGIN, &bob_host, None, 1_000_000)
            .expect("alice: update bob contact with real mailbox_host must succeed");

        // Step 3: add carol as a contact with an unreachable host.
        // Port 19999 is never bound by the test harness; the OS returns
        // "Connection refused" immediately, exercising the failure path.
        let carol_host = "127.0.0.1:19999";
        pair.alice_store
            .lock()
            .expect("alice store lock must not be poisoned")
            .contacts()
            .upsert(CAROL_OWNER_ID, CAROL_LOGIN, carol_host, None, 1_000_000)
            .expect("alice: upsert carol as contact must succeed");

        // Step 4: create the group chat in alice's store and register members.
        let group_chat_id = EXPECTED_GROUP_CHAT_ID;
        {
            let guard = pair
                .alice_store
                .lock()
                .expect("alice store lock must not be poisoned");
            let cs = guard.chats();
            cs.create(group_chat_id, "group", None, 1_000_000)
                .expect("alice: create group chat must succeed");
            cs.add_member(group_chat_id, BOB_OWNER_ID)
                .expect("alice: add bob to group chat must succeed");
            cs.add_member(group_chat_id, CAROL_OWNER_ID)
                .expect("alice: add carol to group chat must succeed");
        }

        // Step 5: alice sends a message to the group chat.
        let request_body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [["Message/set", {
                "accountId": "a-self",
                "create": {
                    "m0": {
                        "chatId": group_chat_id,
                        "body": GROUP_DELIVERY_BODY,
                        "bodyType": "text/plain"
                    }
                }
            }, "0"]]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&request_body)
                    .expect("request body serialization must not fail"),
            ))
            .expect("request construction must not fail");

        let resp = pair
            .alice_router
            .clone()
            .oneshot(req)
            .await
            .expect("alice router oneshot must not fail");

        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "Message/set must return HTTP 200"
        );

        let resp_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("response body must be readable");
        let resp_json: serde_json::Value =
            serde_json::from_slice(&resp_bytes).expect("response must be valid JSON");

        let created = &resp_json["methodResponses"][0][1]["created"];
        assert!(
            created.get("m0").is_some(),
            "Message/set create must succeed; response: {resp_json}"
        );

        let msg_id = created["m0"]["id"]
            .as_str()
            .expect("created.m0.id must be a string")
            .to_string();

        // Pre-delivery oracle: alice's outbox must have 2 rows (bob + carol).
        {
            let guard = pair
                .alice_store
                .lock()
                .expect("alice store lock must not be poisoned");
            let entries = guard
                .outbox()
                .get_by_message(&msg_id)
                .expect("get_by_message must not fail before delivery");
            assert_eq!(
                entries.len(),
                2,
                "oracle: outbox must have 2 rows before delivery"
            );
        }

        // Step 6: run outbox_tick with the real TLS client pinned to bob's cert.
        // Bob's delivery succeeds; carol's fails (no listener at 127.0.0.1:19999).
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let peer_client = PeerHttpClient::new_with_root_cert(&pair.bob_cert_der);
        outbox_tick(&pair.alice_store, &peer_client, ALICE_OWNER_ID, now_unix).await;

        // Step 7: verify bob received the message.
        // Oracle: body matches the hardcoded GROUP_DELIVERY_BODY literal.
        // delivery_state=Received is mandated by Peer/deliver spec step 10.
        {
            let guard = pair
                .bob_store
                .lock()
                .expect("bob store lock must not be poisoned");
            let bob_msg = guard
                .messages()
                .find_by_sender_msg_id(group_chat_id, &msg_id)
                .expect("bob messages().find_by_sender_msg_id must not fail")
                .expect("bob must have the delivered group message");
            assert_eq!(
                bob_msg.body, GROUP_DELIVERY_BODY,
                "oracle: body on bob's side must match the hardcoded expected value"
            );
            assert_eq!(
                bob_msg.delivery_state,
                kith_core::DeliveryState::Received,
                "oracle: delivery_state must be Received after Peer/deliver"
            );
        }

        // Step 8: verify carol's outbox row still exists with attempt_count=1
        // and bob's row is gone.
        {
            let guard = pair
                .alice_store
                .lock()
                .expect("alice store lock must not be poisoned");
            let entries = guard
                .outbox()
                .get_by_message(&msg_id)
                .expect("get_by_message must not fail after delivery");

            let carol_entries: Vec<_> = entries
                .iter()
                .filter(|e| e.peer_user_id == CAROL_OWNER_ID)
                .collect();
            assert_eq!(
                carol_entries.len(),
                1,
                "oracle: carol's outbox row must still exist after bob's successful delivery"
            );
            assert_eq!(
                carol_entries[0].attempt_count, 1,
                "oracle: carol's attempt_count must be 1 after one failed delivery"
            );
            assert_eq!(
                carol_entries[0].kind, "message",
                "oracle: carol's outbox entry must have kind='message'"
            );

            let bob_entries: Vec<_> = entries
                .iter()
                .filter(|e| e.peer_user_id == BOB_OWNER_ID)
                .collect();
            assert!(
                bob_entries.is_empty(),
                "oracle: bob's outbox row must be deleted after successful delivery"
            );
        }
    }
}
