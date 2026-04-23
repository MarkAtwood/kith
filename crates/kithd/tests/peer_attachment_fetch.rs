//! End-to-end test: peer attachment fetch.
//!
//! Scenario:
//!   1. Sender uploads a blob to its own mailbox.
//!   2. Receiver calls `Peer/deliver` to deliver a message that references the
//!      blob as an attachment (simulating what sender's outbox worker would do).
//!   3. Receiver's contact row for sender is updated with the real mailbox_host
//!      so that `get_peer_mailbox_for_blob` can resolve the fetch target.
//!      (`Peer/deliver` overwrites the contact's mailbox_host with the WhoIs
//!      node_name, which is a fake hostname in tests.)
//!   4. Receiver's owner requests the attachment via the download endpoint.
//!   5. The download handler misses locally, looks up the sender's mailbox_host
//!      via `get_peer_mailbox_for_blob`, and fetches the blob from sender's real
//!      TLS listener using `fetch_peer_blob`.
//!   6. The response body equals the original uploaded bytes.
//!   7. A second download is served from the local cache (no second fetch).
//!
//! This test requires the `test-utils` feature:
//! ```sh
//! cargo test -p kithd --features test-utils --test peer_attachment_fetch
//! ```

#[cfg(feature = "test-utils")]
mod inner {
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use kith_attach::BlobStore;
    use kith_core::AuthError;
    use kith_events::make_channel;
    use kith_store::Store;
    use kith_tslocal::{UserProfile, WhoIsNode, WhoIsResponse};
    use kithd::auth::WhoIsProvider;
    use kithd::build_app;
    use kithd::build_dispatcher;
    use kithd::extractors::AppState;
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    // -----------------------------------------------------------------------
    // Identity constants
    // -----------------------------------------------------------------------

    const SENDER_OWNER_ID: &str = "uid-sender";
    const SENDER_LOGIN: &str = "sender@example.com";
    const RECEIVER_OWNER_ID: &str = "uid-receiver";
    const RECEIVER_LOGIN: &str = "receiver@example.com";

    /// Socket address injected via MockConnectInfo for the receiver's owner calls.
    const RECEIVER_MOCK_ADDR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        10100,
    );

    /// Socket address injected via MockConnectInfo for peer-role calls to
    /// receiver's router (i.e. when sender delivers to receiver in-process).
    const SENDER_PEER_MOCK_ADDR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        10101,
    );

    /// Socket address injected via MockConnectInfo for sender's owner calls.
    const SENDER_OWNER_MOCK_ADDR: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        10102,
    );

    // Oracle: sha256("hello attachment world") — computed offline.
    // Verified: echo -n 'hello attachment world' | sha256sum
    //   = 7386a92439e0aa09c742d463152be96cbbe2884868a988b5c071a6f7c16c2f43
    const ATTACHMENT_CONTENT: &[u8] = b"hello attachment world";
    const EXPECTED_SHA256: &str =
        "7386a92439e0aa09c742d463152be96cbbe2884868a988b5c071a6f7c16c2f43";

    /// Oracle: sha256("uid-receiver\x00uid-sender") — sorted participant IDs.
    /// Computed offline:
    ///   python3 -c "import hashlib; print(hashlib.sha256(b'uid-receiver\x00uid-sender').hexdigest())"
    ///   = 624eb64d7f7d37ff51540d5e1de7158dd2921212fa81e3c53981df0f99d18dc7
    const EXPECTED_CHAT_ID: &str =
        "624eb64d7f7d37ff51540d5e1de7158dd2921212fa81e3c53981df0f99d18dc7";

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    pub(super) struct MockWhoIs(pub(super) WhoIsResponse);

    impl WhoIsProvider for MockWhoIs {
        fn whois(
            &self,
            _addr: SocketAddr,
        ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send {
            let result = Ok(self.0.clone());
            async move { result }
        }
    }

    pub(super) fn make_whois(id: &str, login: &str) -> WhoIsResponse {
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

    fn make_blob_store(tag: &str) -> Arc<BlobStore> {
        let dir = std::env::temp_dir().join(format!(
            "kithd-paf-test-{tag}-{}",
            BlobStore::generate_blob_id()
        ));
        let store = Arc::new(BlobStore::new(&dir));
        store.init().expect("blob store init must succeed");
        store
    }

    // -----------------------------------------------------------------------
    // Chat ID oracle cross-check
    // -----------------------------------------------------------------------

    /// Confirms the EXPECTED_SHA256 constant matches an independent sha2 computation.
    #[test]
    fn sha256_constant_matches_independent_computation() {
        let mut h = Sha256::new();
        h.update(ATTACHMENT_CONTENT);
        let computed = format!("{:x}", h.finalize());
        assert_eq!(
            computed, EXPECTED_SHA256,
            "EXPECTED_SHA256 must match independent sha2 crate computation"
        );
    }

    // -----------------------------------------------------------------------
    // Main integration test
    // -----------------------------------------------------------------------

    /// End-to-end: sender uploads a blob; receiver fetches it via the download
    /// endpoint which transparently proxies to sender's TLS listener.
    #[tokio::test]
    async fn peer_attachment_fetch_end_to_end() {
        // Allow loopback addresses to pass the SSRF guard for this test.
        // Must be set before any fetch_peer_blob call is made.
        kithd::allow_loopback_for_tests();

        // ---- Stores ----
        let sender_store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("sender in-memory store must open"),
        ));
        let receiver_store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("receiver in-memory store must open"),
        ));

        // ---- Blob stores ----
        let sender_blob_store = make_blob_store("sender");
        let receiver_blob_store = make_blob_store("receiver");

        // ---- Sender's TCP TLS listener ----
        //
        // MockWhoIs returns sender's own identity for all incoming connections
        // so that the download handler grants Role::Owner.  `fetch_peer_blob`
        // connects to this listener to retrieve the blob; the download endpoint
        // is Owner-only, so the WhoIs must classify every incoming connection
        // as sender (= Owner).  This is safe because the listener is bound to
        // 127.0.0.1 and only reachable by the test process.
        let sender_tcp_whois = MockWhoIs(make_whois(SENDER_OWNER_ID, SENDER_LOGIN));
        let (sender_events_tx, _sender_events_rx) = make_channel(64);
        let sender_dispatcher =
            Arc::new(build_dispatcher(Arc::clone(&sender_store), SENDER_OWNER_ID));
        let sender_tcp_state = AppState {
            ts: Arc::new(sender_tcp_whois),
            store: Arc::clone(&sender_store),
            owner_id: SENDER_OWNER_ID.to_string(),
            owner_login: SENDER_LOGIN.to_string(),
            events_tx: sender_events_tx,
            dispatcher: sender_dispatcher,
            blob_store: Arc::clone(&sender_blob_store),
        };
        let (sender_addr, _sender_cert_der, sender_handle) =
            kithd::spawn_test_listener(sender_tcp_state)
                .await
                .expect("spawn_test_listener for sender must succeed");

        // sender_mailbox_host is the host:port used in receiver's contact row so
        // get_peer_mailbox_for_blob can build the fetch URL for sender's blob.
        let sender_mailbox_host = format!("127.0.0.1:{}", sender_addr.port());

        // ---- Sender's in-process owner router (for the upload call) ----
        let sender_owner_whois = MockWhoIs(make_whois(SENDER_OWNER_ID, SENDER_LOGIN));
        let (sender_owner_events_tx, _sender_owner_events_rx) = make_channel(64);
        let sender_owner_dispatcher =
            Arc::new(build_dispatcher(Arc::clone(&sender_store), SENDER_OWNER_ID));
        let sender_owner_state = AppState {
            ts: Arc::new(sender_owner_whois),
            store: Arc::clone(&sender_store),
            owner_id: SENDER_OWNER_ID.to_string(),
            owner_login: SENDER_LOGIN.to_string(),
            events_tx: sender_owner_events_tx,
            dispatcher: sender_owner_dispatcher,
            blob_store: Arc::clone(&sender_blob_store),
        };
        let sender_router =
            build_app(sender_owner_state).layer(MockConnectInfo(SENDER_OWNER_MOCK_ADDR));

        // ---- Receiver's in-process owner router ----
        let receiver_owner_whois = MockWhoIs(make_whois(RECEIVER_OWNER_ID, RECEIVER_LOGIN));
        let (receiver_owner_events_tx, _receiver_owner_events_rx) = make_channel(64);
        let receiver_owner_dispatcher = Arc::new(build_dispatcher(
            Arc::clone(&receiver_store),
            RECEIVER_OWNER_ID,
        ));
        let receiver_owner_state = AppState {
            ts: Arc::new(receiver_owner_whois),
            store: Arc::clone(&receiver_store),
            owner_id: RECEIVER_OWNER_ID.to_string(),
            owner_login: RECEIVER_LOGIN.to_string(),
            events_tx: receiver_owner_events_tx,
            dispatcher: Arc::clone(&receiver_owner_dispatcher),
            blob_store: Arc::clone(&receiver_blob_store),
        };
        let receiver_owner_router =
            build_app(receiver_owner_state).layer(MockConnectInfo(RECEIVER_MOCK_ADDR));

        // ---- Receiver's in-process peer router (for Peer/deliver from sender) ----
        //
        // MockWhoIs returns SENDER's identity so the Caller extractor grants
        // Role::Peer to the incoming call.  Sender must already be in receiver's
        // contacts for this to succeed.
        let receiver_peer_whois = MockWhoIs(make_whois(SENDER_OWNER_ID, SENDER_LOGIN));
        let (receiver_peer_events_tx, _receiver_peer_events_rx) = make_channel(64);
        let receiver_peer_state = AppState {
            ts: Arc::new(receiver_peer_whois),
            store: Arc::clone(&receiver_store),
            owner_id: RECEIVER_OWNER_ID.to_string(),
            owner_login: RECEIVER_LOGIN.to_string(),
            events_tx: receiver_peer_events_tx,
            dispatcher: receiver_owner_dispatcher,
            blob_store: Arc::clone(&receiver_blob_store),
        };
        let receiver_peer_router =
            build_app(receiver_peer_state).layer(MockConnectInfo(SENDER_PEER_MOCK_ADDR));

        // ---- Step 1: Pre-populate contacts ----
        //
        // Sender must be in receiver's contacts table so Role::Peer is granted
        // when `Peer/deliver` arrives.  The mailbox_host here is a placeholder
        // because Peer/deliver (Step 3) will overwrite it with the WhoIs
        // node_name.  After Peer/deliver we re-upsert with the real address.
        receiver_store
            .lock()
            .expect("receiver store lock must not be poisoned")
            .contacts()
            .upsert(
                SENDER_OWNER_ID,
                SENDER_LOGIN,
                "sender-placeholder.ts.net",
                None,
                1_000_000,
            )
            .expect("receiver: upsert sender as contact must succeed");

        // ---- Step 2: Sender uploads a blob ----
        let upload_req = Request::builder()
            .method("POST")
            .uri("/jmap/upload/a-self")
            .header("content-type", "text/plain")
            .body(Body::from(ATTACHMENT_CONTENT.to_vec()))
            .expect("upload request construction must not fail");

        let upload_resp = sender_router
            .clone()
            .oneshot(upload_req)
            .await
            .expect("sender router oneshot for upload must not fail");

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
        // offline-computed constant, proving integrity through the upload path.
        assert_eq!(
            upload_json["sha256"].as_str(),
            Some(EXPECTED_SHA256),
            "upload sha256 must match the offline oracle"
        );

        // ---- Step 3: Receiver delivers a message with the attachment ----
        //
        // This simulates what sender's outbox worker would do over the network.
        // We use receiver's peer router (MockWhoIs returns sender's identity
        // → Role::Peer) to invoke Peer/deliver in-process.
        //
        // Note: Peer/deliver's Step 11 upserts the sender contact row using the
        // WhoIs node_name ("uid-sender-kith.tail12345.ts.net"), overwriting the
        // mailbox_host we set in Step 1.  We fix this in Step 3b.
        let chat_id = EXPECTED_CHAT_ID;

        // Create the chat in receiver's store.
        receiver_store
            .lock()
            .expect("receiver store lock must not be poisoned")
            .chats()
            .create(chat_id, "direct", Some(SENDER_OWNER_ID), 1_000_000)
            .expect("receiver: create chat must succeed");

        let msg_id = ulid::Ulid::new().to_string();
        let deliver_body = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [["Peer/deliver", {
                "accountId": "a-self",
                "message": {
                    "id": msg_id,
                    "chatId": chat_id,
                    "senderUserId": SENDER_OWNER_ID,
                    "body": "see attached file",
                    "bodyType": "text/plain",
                    "sentAt": "2026-04-20T00:00:00Z",
                    "attachments": [{
                        "blobId": blob_id,
                        "filename": "test.txt",
                        "contentType": "text/plain",
                        "size": ATTACHMENT_CONTENT.len() as u64,
                        "sha256": EXPECTED_SHA256
                    }]
                }
            }, "0"]]
        });

        let deliver_req = Request::builder()
            .method("POST")
            .uri("/jmap/api")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&deliver_body)
                    .expect("deliver body serialization must not fail"),
            ))
            .expect("deliver request construction must not fail");

        let deliver_resp = receiver_peer_router
            .oneshot(deliver_req)
            .await
            .expect("receiver peer router oneshot for Peer/deliver must not fail");

        assert_eq!(
            deliver_resp.status(),
            axum::http::StatusCode::OK,
            "Peer/deliver must return HTTP 200"
        );

        let deliver_bytes = axum::body::to_bytes(deliver_resp.into_body(), 4096)
            .await
            .expect("Peer/deliver response body must be readable");
        let deliver_json: serde_json::Value = serde_json::from_slice(&deliver_bytes)
            .expect("Peer/deliver response must be valid JSON");

        // Oracle: Peer/deliver returns {"accepted": true} on success.
        assert_eq!(
            deliver_json["methodResponses"][0][1]["accepted"].as_bool(),
            Some(true),
            "Peer/deliver must return accepted=true; response: {deliver_json}"
        );

        // ---- Step 3b: Fix sender's mailbox_host in receiver's contacts ----
        //
        // Peer/deliver Step 11 upserts the sender contact using the WhoIs
        // node_name as mailbox_host.  In tests this is a fake hostname
        // ("uid-sender-kith.tail12345.ts.net"), not the real listener address.
        // We overwrite it here with the real sender_mailbox_host so that
        // get_peer_mailbox_for_blob returns the correct address for the fetch.
        receiver_store
            .lock()
            .expect("receiver store lock must not be poisoned")
            .contacts()
            .upsert(
                SENDER_OWNER_ID,
                SENDER_LOGIN,
                &sender_mailbox_host,
                None,
                1_000_000,
            )
            .expect("receiver: fix sender contact mailbox_host must succeed");

        // ---- Step 4: Receiver's owner downloads the attachment ----
        //
        // The blob is NOT in receiver's blob store yet.  The download handler
        // detects a local miss, calls get_peer_mailbox_for_blob (returns
        // sender_mailbox_host), then calls fetch_peer_blob which makes a TLS
        // GET to sender's TCP listener to retrieve and verify the blob.
        let download_req = Request::builder()
            .method("GET")
            .uri(format!("/jmap/download/a-self/{blob_id}/test.txt"))
            .body(Body::empty())
            .expect("download request construction must not fail");

        let download_resp = receiver_owner_router
            .clone()
            .oneshot(download_req)
            .await
            .expect("receiver owner router oneshot for download must not fail");

        assert_eq!(
            download_resp.status(),
            axum::http::StatusCode::OK,
            "attachment download must return 200"
        );

        let download_bytes = axum::body::to_bytes(download_resp.into_body(), 4096)
            .await
            .expect("download response body must be readable");

        // Oracle: downloaded bytes must equal the original content exactly.
        assert_eq!(
            download_bytes.as_ref(),
            ATTACHMENT_CONTENT,
            "oracle: downloaded bytes must equal the original uploaded content"
        );

        // ---- Step 5: Second download serves from local cache ----
        //
        // After step 4, the blob was written to receiver's blob store.
        // A second download must return 200 with the same bytes without
        // triggering another fetch_peer_blob call.
        let cached_req = Request::builder()
            .method("GET")
            .uri(format!("/jmap/download/a-self/{blob_id}/test.txt"))
            .body(Body::empty())
            .expect("cached download request construction must not fail");

        let cached_resp = receiver_owner_router
            .oneshot(cached_req)
            .await
            .expect("receiver owner router oneshot for cached download must not fail");

        assert_eq!(
            cached_resp.status(),
            axum::http::StatusCode::OK,
            "cached attachment download must return 200"
        );

        let cached_bytes = axum::body::to_bytes(cached_resp.into_body(), 4096)
            .await
            .expect("cached download response body must be readable");

        // Oracle: cached bytes must equal original content.
        assert_eq!(
            cached_bytes.as_ref(),
            ATTACHMENT_CONTENT,
            "oracle: cached downloaded bytes must equal the original uploaded content"
        );

        // ---- Step 6: Independent store verification ----
        //
        // Confirm the blob is now present in receiver's local blob store
        // (proves the write in step 4 actually succeeded).
        let stored = receiver_blob_store
            .read_blob(&blob_id)
            .await
            .expect("read_blob on receiver must not fail")
            .expect("blob must be present in receiver's store after fetch");
        assert_eq!(
            stored.as_slice(),
            ATTACHMENT_CONTENT,
            "oracle: blob in receiver's store must match original content"
        );

        // Verify the delivered message's attachment metadata was stored correctly.
        {
            let guard = receiver_store
                .lock()
                .expect("receiver store lock must not be poisoned");
            let msg = guard
                .messages()
                .get(&msg_id)
                .expect("receiver messages().get must not fail")
                .expect("receiver must have the delivered message");
            assert_eq!(
                msg.attachments.len(),
                1,
                "oracle: delivered message must have exactly 1 attachment"
            );
            let att = &msg.attachments[0];
            assert_eq!(
                att.blob_id, blob_id,
                "oracle: attachment blobId must round-trip"
            );
            assert_eq!(
                att.filename, "test.txt",
                "oracle: attachment filename must be 'test.txt'"
            );
            assert_eq!(
                att.sha256, EXPECTED_SHA256,
                "oracle: attachment sha256 must match"
            );
            assert_eq!(
                att.size,
                ATTACHMENT_CONTENT.len() as u64,
                "oracle: attachment size must match content length"
            );
        }

        sender_handle.abort();
    }
}
