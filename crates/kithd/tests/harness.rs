//! Integration test harness for kithd.
//!
//! # Running these tests
//!
//! All tests in this file require the `test-utils` feature:
//! ```sh
//! cargo test -p kithd --features test-utils
//! ```
//! `cargo test -p kithd` (without the feature) will compile but skip all tests here.

/// Integration test harness: alice + bob test pair.
///
/// Alice runs in-process (no TCP).  Test code calls her router directly via
/// `.oneshot(request)` with `MockConnectInfo` injecting `ALICE_MOCK_ADDR`.
/// Alice's `MockWhoIs` always returns alice's identity for any address, so
/// all in-process requests to alice's router are classified as Owner.
///
/// Bob runs with a real TCP listener via `spawn_test_listener`.  Alice's
/// outbox worker delivers to bob over TCP.  From bob's perspective every
/// incoming TCP connection from 127.0.0.1 is alice delivering, so bob's
/// `MockWhoIs` returns alice's identity for all addresses.  Bob also has an
/// in-process router for assertion reads; its `MockWhoIs` returns bob's own
/// identity so that bob is Owner on those calls.
///
/// Only compiled under `#[cfg(feature = "test-utils")]` because
/// `spawn_test_listener` is only available with that feature.
#[cfg(feature = "test-utils")]
mod inner {
    use axum::extract::connect_info::MockConnectInfo;
    use axum::Router;
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
    use tokio::task::JoinHandle;

    // -----------------------------------------------------------------------
    // Identity constants
    // -----------------------------------------------------------------------

    pub const ALICE_OWNER_ID: &str = "uid-alice";
    pub const ALICE_LOGIN: &str = "alice@example.com";
    pub const BOB_OWNER_ID: &str = "uid-bob";
    pub const BOB_LOGIN: &str = "bob@example.com";

    /// Fixed socket address injected via `MockConnectInfo` for owner-API calls
    /// to alice's in-process router.
    /// Independent oracle: sha256("\x00".join(sorted(["uid-alice", "uid-bob"])))
    /// Computed offline: echo -ne "uid-alice\x00uid-bob" | sha256sum

    fn make_blob_store() -> std::sync::Arc<kith_attach::BlobStore> {
        let dir = std::env::temp_dir().join(format!(
            "kithd-test-blobs-{}",
            kith_attach::BlobStore::generate_blob_id()
        ));
        let store = std::sync::Arc::new(kith_attach::BlobStore::new(&dir));
        store.init().expect("blob store init must succeed");
        store
    }

    pub const EXPECTED_CHAT_ID: &str =
        "d4f2c256272c172cb98fb77fd336bb46e22dc9976d03861fe8fc46c774c03eb0";

    pub const ALICE_MOCK_ADDR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        10001,
    );

    /// Fixed socket address injected via `MockConnectInfo` for owner-API calls
    /// to bob's in-process assertion router.
    pub const BOB_MOCK_ADDR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        10002,
    );

    // -----------------------------------------------------------------------
    // Test double: MockWhoIs
    //
    // Returns a fixed `WhoIsResponse` for any address.
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

    // -----------------------------------------------------------------------
    // TestPair
    // -----------------------------------------------------------------------

    /// A paired alice+bob test instance.
    ///
    /// Alice is in-process; bob has a real TCP listener.
    pub struct TestPair {
        /// Alice's in-memory store (shared with alice's router).
        pub alice_store: Arc<Mutex<Store>>,
        /// Alice's in-process router.  Call `.clone().oneshot(req)` from tests.
        /// `MockConnectInfo(ALICE_MOCK_ADDR)` is already attached; alice is always Owner.
        pub alice_router: Router,

        /// Bob's in-memory store (shared between bob's TCP listener and bob's assertion router).
        pub bob_store: Arc<Mutex<Store>>,
        /// Address of bob's real HTTPS TCP listener.
        pub bob_addr: SocketAddr,
        /// DER-encoded self-signed certificate for bob's listener.
        /// Pass to `PeerHttpClient::new_with_root_cert` when delivering to bob over TLS.
        pub bob_cert_der: Vec<u8>,
        /// Bob's in-process router for assertion reads.
        /// `MockConnectInfo(BOB_MOCK_ADDR)` is already attached; bob is always Owner on these.
        pub bob_router: Router,

        /// Join handle for bob's TCP listener task.  Aborted in `Drop`.
        bob_handle: Option<JoinHandle<()>>,
    }

    impl Drop for TestPair {
        fn drop(&mut self) {
            if let Some(h) = self.bob_handle.take() {
                h.abort();
            }
        }
    }

    /// Build a TestPair with alice (in-process) and bob (real TCP listener).
    ///
    /// Pre-populates alice's contacts with bob and bob's contacts with alice
    /// so that peer delivery authorization succeeds without extra setup in
    /// each test.
    pub async fn spawn_test_pair() -> TestPair {
        // ---- alice's in-memory store ----
        let alice_store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("alice in-memory store must open"),
        ));

        // ---- bob's in-memory store ----
        let bob_store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("bob in-memory store must open"),
        ));

        // Pre-populate contacts: alice knows bob, bob knows alice.
        //
        // For alice: bob's mailbox_host is set to the loopback addr that will
        // be known after spawn_test_listener.  We use a placeholder here and
        // do NOT update it afterwards — outbox_tick tests are responsible for
        // setting the correct host themselves.  The TestPair exposes bob_addr
        // so test code can do the update.
        //
        // For bob: alice's mailbox_host is irrelevant for inbound delivery
        // (bob receives from alice, alice doesn't need to deliver to bob via
        // the outbox in the smoke test).  A placeholder is fine.
        alice_store
            .lock()
            .expect("alice store lock must not be poisoned")
            .contacts()
            .upsert(
                BOB_OWNER_ID,
                BOB_LOGIN,
                "bob-kith.placeholder.ts.net",
                None,
                1_000_000,
            )
            .expect("alice: upsert bob as contact must succeed");

        bob_store
            .lock()
            .expect("bob store lock must not be poisoned")
            .contacts()
            .upsert(
                ALICE_OWNER_ID,
                ALICE_LOGIN,
                "alice-kith.placeholder.ts.net",
                None,
                1_000_000,
            )
            .expect("bob: upsert alice as contact must succeed");

        // ---- alice's WhoIs: always returns alice ----
        let alice_whois = MockWhoIs(make_whois(ALICE_OWNER_ID, ALICE_LOGIN));

        // ---- alice's AppState ----
        let (alice_events_tx, _alice_events_rx) = make_channel(64);
        let alice_dispatcher = Arc::new(build_dispatcher(Arc::clone(&alice_store), ALICE_OWNER_ID));
        let alice_state = AppState {
            ts: Arc::new(alice_whois),
            store: Arc::clone(&alice_store),
            owner_id: ALICE_OWNER_ID.to_string(),
            owner_login: ALICE_LOGIN.to_string(),
            events_tx: alice_events_tx,
            dispatcher: alice_dispatcher,
            blob_store: make_blob_store(),
        };

        // ---- alice's in-process router ----
        let alice_router = build_app(alice_state).layer(MockConnectInfo(ALICE_MOCK_ADDR));

        // ---- bob's TCP listener WhoIs: returns alice for all connections ----
        //
        // All TCP connections to bob's listener originate from 127.0.0.1
        // (the outbox worker running in the test process).  The only peer
        // that ever connects to bob in these tests is alice, so returning
        // alice's identity unconditionally is correct.
        let bob_tcp_whois = MockWhoIs(make_whois(ALICE_OWNER_ID, ALICE_LOGIN));

        // ---- bob's AppState for the TCP listener ----
        let (bob_events_tx, _bob_events_rx) = make_channel(64);
        let bob_dispatcher = Arc::new(build_dispatcher(Arc::clone(&bob_store), BOB_OWNER_ID));
        let bob_tcp_state = AppState {
            ts: Arc::new(bob_tcp_whois),
            store: Arc::clone(&bob_store),
            owner_id: BOB_OWNER_ID.to_string(),
            owner_login: BOB_LOGIN.to_string(),
            events_tx: bob_events_tx,
            dispatcher: Arc::clone(&bob_dispatcher),
            blob_store: make_blob_store(),
        };

        // ---- spawn bob's real TCP listener ----
        let (bob_addr, bob_cert_der, bob_handle) = kithd::spawn_test_listener(bob_tcp_state)
            .await
            .expect("spawn_test_listener for bob must succeed");

        // ---- bob's in-process assertion router ----
        //
        // Uses a separate MockWhoIs that returns bob's own identity so that
        // assertion calls (e.g. Message/get to verify a message arrived) are
        // classified as Owner on bob's router.
        let bob_assert_whois = MockWhoIs(make_whois(BOB_OWNER_ID, BOB_LOGIN));
        let (bob_assert_events_tx, _bob_assert_events_rx) = make_channel(64);
        let bob_assert_state = AppState {
            ts: Arc::new(bob_assert_whois),
            store: Arc::clone(&bob_store),
            owner_id: BOB_OWNER_ID.to_string(),
            owner_login: BOB_LOGIN.to_string(),
            events_tx: bob_assert_events_tx,
            dispatcher: bob_dispatcher,
            blob_store: make_blob_store(),
        };
        let bob_router = build_app(bob_assert_state).layer(MockConnectInfo(BOB_MOCK_ADDR));

        TestPair {
            alice_store,
            alice_router,
            bob_store,
            bob_addr,
            bob_cert_der,
            bob_router,
            bob_handle: Some(bob_handle),
        }
    }
}

#[cfg(feature = "test-utils")]
#[allow(unused_imports)]
pub use inner::{
    spawn_test_pair, TestPair, ALICE_LOGIN, ALICE_MOCK_ADDR, ALICE_OWNER_ID, BOB_LOGIN,
    BOB_MOCK_ADDR, BOB_OWNER_ID, EXPECTED_CHAT_ID,
};

// ---------------------------------------------------------------------------
// Smoke test: verify the harness constructs and bob's listener is reachable.
// ---------------------------------------------------------------------------

/// Verifies harness-specific postconditions after `spawn_test_pair`:
/// both stores start empty (message state = "s-0") and the contacts table
/// contains the pre-populated alice↔bob entries.
///
/// Listener binding (loopback addr, non-zero port, cert_der, TCP connect)
/// is covered by `spawn_test_listener_binds_loopback_port` in e2e.rs and
/// is not duplicated here.
///
/// All assertions read directly from SQLite — no application response path
/// is exercised.
#[cfg(feature = "test-utils")]
#[tokio::test]
async fn harness_smoke_test() {
    let pair = inner::spawn_test_pair().await;

    // Listener binding (loopback addr, non-zero port, cert_der, TCP connect)
    // is covered by spawn_test_listener_binds_loopback_port in e2e.rs.
    // This test checks only the harness-specific state below.

    // Oracle 1: alice's message store starts at state "s-0" (no messages yet).
    let alice_msg_state = pair
        .alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .messages()
        .get_state()
        .expect("alice get_state must succeed");
    assert_eq!(
        alice_msg_state, "s-0",
        "alice message state must be s-0 on fresh harness"
    );

    // Oracle 2: bob's message store starts at state "s-0" (no messages yet).
    let bob_msg_state = pair
        .bob_store
        .lock()
        .expect("bob store lock must not be poisoned")
        .messages()
        .get_state()
        .expect("bob get_state must succeed");
    assert_eq!(
        bob_msg_state, "s-0",
        "bob message state must be s-0 on fresh harness"
    );

    // Oracle 3: alice's contacts contain bob (pre-populated by spawn_test_pair).
    let bob_in_alice = pair
        .alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .contacts()
        .is_permitted(inner::BOB_OWNER_ID)
        .expect("is_permitted must not fail");
    assert!(
        bob_in_alice,
        "bob must be in alice's contacts after harness setup"
    );

    // Oracle 4: bob's contacts contain alice (pre-populated by spawn_test_pair).
    let alice_in_bob = pair
        .bob_store
        .lock()
        .expect("bob store lock must not be poisoned")
        .contacts()
        .is_permitted(inner::ALICE_OWNER_ID)
        .expect("is_permitted must not fail");
    assert!(
        alice_in_bob,
        "alice must be in bob's contacts after harness setup"
    );
}

// ---------------------------------------------------------------------------
// Full delivery test: alice → outbox_tick → bob
// ---------------------------------------------------------------------------

/// Oracle: the message body "EXPECTED_BODY" is a hardcoded constant never derived
/// from alice's store.  After `outbox_tick`, bob's store is read directly and the
/// body is compared against that constant.  `DeliveryState::Received` is the
/// expected state per Peer/deliver spec (kith-architecture.md §Wire Protocol
/// step 10).  Alice's outbox row being absent after the tick proves
/// `complete_delivery` ran (outbox DELETE + messages.delivery_state update are
/// atomic in a transaction).
#[cfg(feature = "test-utils")]
#[tokio::test]
async fn full_message_delivery() {
    use axum::body::Body;
    use axum::http::Request;
    use kith_core::DeliveryState;
    use kith_peer::{outbox_tick, PeerHttpClient};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    // The hardcoded oracle: this body value must match what bob's store contains.
    const EXPECTED_BODY: &str = "hello from alice";

    // Step 1: build the test pair.
    let pair = inner::spawn_test_pair().await;

    // Step 2: hardcoded chat ID — independent oracle, not derived from compute_chat_id.
    // Validated against compute_chat_id in chat_id_matches_expected_constant.
    let chat_id = inner::EXPECTED_CHAT_ID;

    // Step 3: update alice's contact for bob with the real loopback address so
    // outbox_tick can form "https://127.0.0.1:{port}/jmap/api".
    let bob_mailbox_host = format!("127.0.0.1:{}", pair.bob_addr.port());
    pair.alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .contacts()
        .upsert(
            inner::BOB_OWNER_ID,
            inner::BOB_LOGIN,
            &bob_mailbox_host,
            None,
            1_000_000,
        )
        .expect("alice: update bob contact with real mailbox_host must succeed");

    // Step 4: create the alice↔bob chat in alice's store.
    // Message/set create returns notFound if the chat doesn't exist.
    pair.alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .chats()
        .create(&chat_id, "direct", Some(inner::BOB_OWNER_ID), 1_000_000)
        .expect("alice: create chat must succeed");

    // Step 5: send Message/set create to alice's in-process router.
    // alice_router already has MockConnectInfo(ALICE_MOCK_ADDR) → Owner classification.
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
            serde_json::to_string(&request_body).expect("request body serialization must not fail"),
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

    // Step 6: assert the message was created (not in notCreated).
    let created = &resp_json["methodResponses"][0][1]["created"];
    assert!(
        created.get("m0").is_some(),
        "Message/set create must succeed: created.m0 must be present; response: {resp_json}"
    );
    assert!(
        resp_json["methodResponses"][0][1]["notCreated"]
            .get("m0")
            .is_none(),
        "notCreated.m0 must be absent; response: {resp_json}"
    );

    let msg_id = created["m0"]["id"]
        .as_str()
        .expect("created.m0.id must be a string")
        .to_string();

    // Step 7: alice's outbox must have exactly one entry for this message.
    {
        let guard = pair
            .alice_store
            .lock()
            .expect("alice store lock must not be poisoned");
        let entries = guard
            .outbox()
            .get_by_message(&msg_id)
            .expect("outbox get_by_message must not fail");
        assert!(
            !entries.is_empty(),
            "outbox must have a pending entry for the created message"
        );
        assert_eq!(
            entries[0].peer_user_id,
            inner::BOB_OWNER_ID,
            "outbox entry peer_user_id must be bob's"
        );
    }

    // Step 8: deliver via outbox_tick using the real TLS client pinned to bob's cert.
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let peer_client = PeerHttpClient::new_with_root_cert(&pair.bob_cert_der);
    outbox_tick(
        &pair.alice_store,
        &peer_client,
        inner::ALICE_OWNER_ID,
        now_unix,
    )
    .await;

    // Step 9: alice's outbox row must be gone (complete_delivery ran).
    {
        let guard = pair
            .alice_store
            .lock()
            .expect("alice store lock must not be poisoned after tick");
        let entries = guard
            .outbox()
            .get_by_message(&msg_id)
            .expect("outbox get_by_message must not fail after tick");
        assert!(
            entries.is_empty(),
            "outbox row must be deleted after successful delivery"
        );
    }

    // Step 10: bob's store must contain the message with the expected oracle values.
    {
        let guard = pair
            .bob_store
            .lock()
            .expect("bob store lock must not be poisoned");
        let bob_msg = guard
            .messages()
            .get(&msg_id)
            .expect("bob messages().get must not fail")
            .expect("bob must have the delivered message");

        // Oracle: body is a hardcoded constant, not derived from alice's store.
        assert_eq!(
            bob_msg.body, EXPECTED_BODY,
            "oracle: body on bob's side must match the hardcoded expected value"
        );
        // Oracle: Peer/deliver spec mandates delivery_state = Received (step 10).
        assert_eq!(
            bob_msg.delivery_state,
            DeliveryState::Received,
            "oracle: delivery_state must be Received after Peer/deliver"
        );
        // Oracle: sender_id must be alice's tailscale user ID (set by DeliverHandler step 10).
        assert_eq!(
            bob_msg.sender_id,
            inner::ALICE_OWNER_ID,
            "oracle: sender_id on bob's side must be alice's user ID"
        );
    }
}

// ---------------------------------------------------------------------------
// Offline delivery and outbox retry test.
//
// Verifies that the outbox retry loop correctly records failures when delivery
// is impossible, and succeeds when the peer becomes available.
//
// Algorithm:
//   1. spawn_test_pair() — alice and bob are both set up.
//   2. Update alice's contact for bob so mailbox_host is bob's real loopback
//      addr.  outbox_tick reads mailbox_host from contacts at tick time and
//      forms https://{mailbox_host}/jmap/api.
//   3. Insert a chat + message into alice's store and enqueue in alice's outbox.
//   4. Tick 1 with FailingClient (always returns a network error) to simulate
//      bob being unreachable.  Verify: outbox row still present with
//      attempt_count=1, message still Pending.
//   5. Tick 2 with real PeerHttpClient pinned to bob's cert (bob is reachable).
//      Pass a far-future now_unix so the backed-off entry is due.
//      Verify: outbox row deleted, bob has message with body "offline-test"
//      and delivery_state=Received.
//
// Independent oracles:
//   - attempt_count=1 is read back from SQLite via get_by_message; it is not
//     derived from any delivery code path.
//   - body="offline-test" is a hardcoded literal inserted before any tick runs.
//   - delivery_state=Received is the state DeliverHandler mandates for all
//     inbound messages (spec step 10).

/// A `DeliverClient` that always returns a network error, simulating an
/// offline peer.
#[cfg(feature = "test-utils")]
struct FailingClient;

#[cfg(feature = "test-utils")]
impl kith_peer::DeliverClient for FailingClient {
    fn deliver_msg<'a>(
        &'a self,
        _url: &'a str,
        _request: serde_json::Value,
    ) -> impl std::future::Future<Output = Result<(), kith_peer::PeerDeliveryError>> + Send + 'a
    {
        async {
            Err(kith_peer::PeerDeliveryError::Network(
                "simulated offline".into(),
            ))
        }
    }
}

#[cfg(feature = "test-utils")]
#[tokio::test]
async fn offline_delivery_and_retry() {
    use kith_core::DeliveryState;
    use kith_peer::{outbox_tick, PeerHttpClient};
    use ulid::Ulid;

    let pair = inner::spawn_test_pair().await;

    // STEP 1: Point alice's contact for bob at the real listener address.
    // spawn_test_pair sets a placeholder; we overwrite it here so that
    // outbox_tick can form a valid https://127.0.0.1:{port}/jmap/api URL.
    let bob_host = format!("127.0.0.1:{}", pair.bob_addr.port());
    pair.alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .contacts()
        .upsert(
            inner::BOB_OWNER_ID,
            inner::BOB_LOGIN,
            &bob_host,
            None,
            1_000_000,
        )
        .expect("alice: update bob's mailbox_host to real listener addr");

    // STEP 2: Insert chat + message into alice's store and enqueue in outbox.
    // chat_id is a hardcoded oracle, not derived from compute_chat_id.
    // Validated against compute_chat_id in chat_id_matches_expected_constant.
    let chat_id = inner::EXPECTED_CHAT_ID;
    let msg_id = Ulid::new().to_string();
    // Unix timestamp in seconds; arbitrary past value used for initial row creation.
    let now: i64 = 1_000_000;

    {
        let guard = pair
            .alice_store
            .lock()
            .expect("alice store lock must not be poisoned");

        guard
            .chats()
            .create(&chat_id, "direct", Some(inner::BOB_OWNER_ID), now)
            .expect("alice: create chat must succeed");

        guard
            .messages()
            .insert(
                &msg_id,
                &chat_id,
                "self",
                "offline-test",
                "text/plain",
                None,
                now,
                &DeliveryState::Pending,
                None,
            )
            .expect("alice: insert message must succeed");

        guard
            .outbox()
            .enqueue(&msg_id, inner::BOB_OWNER_ID, &bob_host, now)
            .expect("alice: enqueue message must succeed");
    }

    // STEP 3: Tick 1 — offline simulation via FailingClient.
    // FailingClient returns PeerDeliveryError::Network unconditionally,
    // causing outbox_tick to call record_failure.
    outbox_tick(
        &pair.alice_store,
        &FailingClient,
        inner::ALICE_OWNER_ID,
        now,
    )
    .await;

    // Oracle 1: outbox row must still exist with attempt_count=1.
    // This value comes from SQLite via get_by_message; it is not derived
    // from any code path in the delivery logic.
    let entries_after_fail = pair
        .alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .outbox()
        .get_by_message(&msg_id)
        .expect("get_by_message must not fail after failed tick");
    assert!(
        !entries_after_fail.is_empty(),
        "outbox row must still exist after one failed delivery attempt"
    );
    let entry_after_fail = &entries_after_fail[0];

    assert_eq!(
        entry_after_fail.attempt_count, 1,
        "attempt_count must be 1 after the first failed tick"
    );

    // Oracle 2: message delivery_state must still be Pending.
    // Pending means not yet delivered, not failed; retry will continue.
    let msg_after_fail = pair
        .alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .messages()
        .get(&msg_id)
        .expect("get must not fail")
        .expect("message must still exist after a failed tick");

    assert_eq!(
        msg_after_fail.delivery_state,
        DeliveryState::Pending,
        "delivery_state must remain Pending after one failed tick"
    );

    // STEP 4: Tick 2 — real delivery.
    // Far-future timestamp: ensures outbox row is due regardless of backoff.
    // Invariant: value must exceed now_actual + max_backoff_with_jitter.
    // Max backoff cap is 3600s × 1.2 jitter = 4320s. 1_000_000_000 >> 4320.
    // PeerHttpClient with bob's pinned cert connects to bob's real listener.
    let now2: i64 = 1_000_000_000;
    let client = PeerHttpClient::new_with_root_cert(&pair.bob_cert_der);
    outbox_tick(&pair.alice_store, &client, inner::ALICE_OWNER_ID, now2).await;

    // Oracle 3: outbox row must be deleted (complete_delivery ran the atomic
    // transaction that DELETEs the row and sets delivery_state=Delivered on
    // alice's message).
    let entry_after_success = pair
        .alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .outbox()
        .get_by_message(&msg_id)
        .expect("get_by_message must not fail after successful tick");

    assert!(
        entry_after_success.is_empty(),
        "outbox row must be deleted after successful delivery"
    );

    // Oracle 4: bob's store must contain the message with the hardcoded body.
    // "offline-test" is the body literal we inserted; the fact that bob has
    // it proves end-to-end delivery through the real Peer/deliver handler, not
    // a mock.
    let bob_msg = pair
        .bob_store
        .lock()
        .expect("bob store lock must not be poisoned")
        .messages()
        .get(&msg_id)
        .expect("get on bob's store must not fail")
        .expect("bob must have received the message after successful tick");

    assert_eq!(
        bob_msg.body, "offline-test",
        "oracle: bob must have received the message with body 'offline-test'"
    );

    // Oracle 5: delivery_state on bob's side must be Received.
    // Received is what DeliverHandler writes for all inbound messages (spec
    // step 10).  This distinguishes a real Peer/deliver call from anything
    // that might merely create a row in bob's store.
    assert_eq!(
        bob_msg.delivery_state,
        DeliveryState::Received,
        "oracle: bob's message must have delivery_state=Received"
    );
}

// ---------------------------------------------------------------------------
// Delivery with attachment test: alice uploads a blob, creates a message
// referencing it, and delivers to bob.  Bob's store must contain the message
// with the attachment metadata preserved verbatim.
//
// Independent oracles:
//   - sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
//     Computed offline: printf 'hello' | sha256sum
//   - blobId is opaque but must be non-empty (returned by the upload endpoint)
//   - filename "hello.txt", contentType "text/plain", size 5 are hardcoded
//     literals in the Message/set request, never derived from the code path
//     under test.
//   - Bob's delivery_state=Received is mandated by Peer/deliver spec step 10.
// ---------------------------------------------------------------------------

/// Verify that an attachment uploaded by alice survives the full delivery
/// pipeline and arrives at bob's store with all metadata intact.
#[cfg(feature = "test-utils")]
#[tokio::test]
async fn full_message_delivery_with_attachment() {
    use axum::body::Body;
    use axum::http::Request;
    use kith_peer::{outbox_tick, PeerHttpClient};
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    // Independent oracle: sha256 of b"hello" computed offline.
    // printf 'hello' | sha256sum → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    const EXPECTED_SHA256: &str =
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    // Runtime recompute to confirm the constant above is correct.
    {
        let mut h = Sha256::new();
        h.update(b"hello");
        let computed = format!("{:x}", h.finalize());
        assert_eq!(
            computed, EXPECTED_SHA256,
            "EXPECTED_SHA256 constant must match independent sha2 computation"
        );
    }

    // Step 1: build the test pair.
    let pair = inner::spawn_test_pair().await;

    // Step 2: upload a blob to alice's in-process router.
    // The router already has MockConnectInfo(ALICE_MOCK_ADDR) → Owner role.
    let upload_req = Request::builder()
        .method("POST")
        .uri("/jmap/upload/a-self")
        .header("content-type", "text/plain")
        .body(Body::from(b"hello".to_vec()))
        .expect("upload request construction must not fail");

    let upload_resp = pair
        .alice_router
        .clone()
        .oneshot(upload_req)
        .await
        .expect("alice router oneshot for upload must not fail");

    assert_eq!(
        upload_resp.status(),
        axum::http::StatusCode::CREATED,
        "blob upload must return 201 Created"
    );

    let upload_bytes = axum::body::to_bytes(upload_resp.into_body(), 4096)
        .await
        .expect("upload response body must be readable");
    let upload_json: serde_json::Value =
        serde_json::from_slice(&upload_bytes).expect("upload response must be valid JSON");

    let blob_id = upload_json["blobId"]
        .as_str()
        .expect("upload response must contain blobId")
        .to_string();
    assert!(!blob_id.is_empty(), "blobId must be non-empty");

    // Oracle: the sha256 returned by the upload endpoint must match the
    // independent computation above.  The upload handler computes it from
    // the same bytes that were written to disk, so the client can verify
    // the transfer without re-downloading.
    assert_eq!(
        upload_json["sha256"].as_str(),
        Some(EXPECTED_SHA256),
        "upload sha256 must match offline-computed oracle"
    );

    // Step 3: update alice's contact for bob with the real loopback address.
    let bob_mailbox_host = format!("127.0.0.1:{}", pair.bob_addr.port());
    pair.alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .contacts()
        .upsert(
            inner::BOB_OWNER_ID,
            inner::BOB_LOGIN,
            &bob_mailbox_host,
            None,
            1_000_000,
        )
        .expect("alice: update bob contact with real mailbox_host must succeed");

    // Step 4: create the alice↔bob chat in alice's store.
    let chat_id = inner::EXPECTED_CHAT_ID;
    pair.alice_store
        .lock()
        .expect("alice store lock must not be poisoned")
        .chats()
        .create(&chat_id, "direct", Some(inner::BOB_OWNER_ID), 1_000_000)
        .expect("alice: create chat must succeed");

    // Step 5: create a message with the uploaded attachment via Message/set.
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Message/set", {
            "accountId": "a-self",
            "create": {
                "m0": {
                    "chatId": chat_id,
                    "body": "see attached",
                    "bodyType": "text/plain",
                    "attachments": [{
                        "blobId": blob_id,
                        "filename": "hello.txt",
                        "contentType": "text/plain",
                        "size": 5u64,
                        "sha256": EXPECTED_SHA256
                    }]
                }
            }
        }, "0"]]
    });

    let msg_req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&request_body).expect("request body serialization must not fail"),
        ))
        .expect("request construction must not fail");

    let msg_resp = pair
        .alice_router
        .clone()
        .oneshot(msg_req)
        .await
        .expect("alice router oneshot for Message/set must not fail");

    assert_eq!(
        msg_resp.status(),
        axum::http::StatusCode::OK,
        "Message/set must return HTTP 200"
    );

    let msg_resp_bytes = axum::body::to_bytes(msg_resp.into_body(), 1024 * 1024)
        .await
        .expect("Message/set response body must be readable");
    let msg_resp_json: serde_json::Value =
        serde_json::from_slice(&msg_resp_bytes).expect("Message/set response must be valid JSON");

    let created = &msg_resp_json["methodResponses"][0][1]["created"];
    assert!(
        created.get("m0").is_some(),
        "Message/set create must succeed; response: {msg_resp_json}"
    );
    assert!(
        msg_resp_json["methodResponses"][0][1]["notCreated"]
            .get("m0")
            .is_none(),
        "notCreated.m0 must be absent; response: {msg_resp_json}"
    );

    let msg_id = created["m0"]["id"]
        .as_str()
        .expect("created.m0.id must be a string")
        .to_string();

    // Step 6: deliver via outbox_tick using the real TLS client pinned to bob's cert.
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let peer_client = PeerHttpClient::new_with_root_cert(&pair.bob_cert_der);
    outbox_tick(
        &pair.alice_store,
        &peer_client,
        inner::ALICE_OWNER_ID,
        now_unix,
    )
    .await;

    // Step 7: alice's outbox row must be gone (delivery succeeded).
    {
        let guard = pair
            .alice_store
            .lock()
            .expect("alice store lock must not be poisoned after tick");
        let entries = guard
            .outbox()
            .get_by_message(&msg_id)
            .expect("outbox get_by_message must not fail after tick");
        assert!(
            entries.is_empty(),
            "outbox row must be deleted after successful delivery"
        );
    }

    // Step 8: verify bob's store has the message with the attachment.
    {
        let guard = pair
            .bob_store
            .lock()
            .expect("bob store lock must not be poisoned");

        let bob_msg = guard
            .messages()
            .get(&msg_id)
            .expect("bob messages().get must not fail")
            .expect("bob must have the delivered message");

        // Oracle: delivery_state=Received is mandated by Peer/deliver spec step 10.
        assert_eq!(
            bob_msg.delivery_state,
            kith_core::DeliveryState::Received,
            "oracle: delivery_state must be Received after Peer/deliver"
        );

        // Oracle: exactly one attachment.
        assert_eq!(
            bob_msg.attachments.len(),
            1,
            "oracle: bob's message must have exactly 1 attachment"
        );

        let att = &bob_msg.attachments[0];

        // Oracle: blobId is the opaque ID returned by alice's upload endpoint.
        // It must match exactly because outbox_tick serializes it from alice's
        // message row and DeliverHandler stores whatever the wire supplies.
        assert_eq!(
            att.blob_id, blob_id,
            "oracle: attachment blobId on bob's side must match what alice uploaded"
        );

        // Oracle: filename, contentType, size are hardcoded in the Message/set
        // request above — independent of any code path under test.
        assert_eq!(
            att.filename, "hello.txt",
            "oracle: attachment filename must be 'hello.txt'"
        );
        assert_eq!(
            att.content_type, "text/plain",
            "oracle: attachment contentType must be 'text/plain'"
        );
        assert_eq!(att.size, 5u64, "oracle: attachment size must be 5");

        // Oracle: sha256 must match the independently computed value for b"hello".
        // This is the primary integrity check: if the sha256 round-trips correctly
        // through alice's Message/set → outbox wire format → bob's DeliverHandler,
        // the attachment metadata pipeline is correct end-to-end.
        assert_eq!(
            att.sha256, EXPECTED_SHA256,
            "oracle: attachment sha256 must match offline-computed sha256('hello')"
        );
    }
}
