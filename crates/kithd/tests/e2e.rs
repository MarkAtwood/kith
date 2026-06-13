/// End-to-end tests for the kithd axum request pipeline.
///
/// These tests exercise the full stack:
///   HTTP request → MockConnectInfo → Caller extractor (WhoIs → classify)
///                → handler (session / jmap dispatch) → Store → response
///
/// No real Tailscale daemon is required: `MockWhoIs` returns a fixed identity
/// for any address, and `MockConnectInfo` feeds a fixed peer address into the
/// `ConnectInfo<SocketAddr>` extractor.
///
/// Oracles are independent of the implementation:
/// - Session endpoint: RFC 8620 §2 field list and required capability URN.
/// - Contact/get response: RFC 8620 §5.1 methodResponses envelope shape.
/// - unknownMethod error: RFC 8620 §7.1 error type string.
/// - Unauthorized: HTTP 401 status code for a caller that is neither owner
///   nor in contacts.
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use kith_core::AuthError;
use kith_events::make_channel;
#[cfg(feature = "test-utils")]
use kith_peer;
use kith_store::Store;
use kith_tslocal::{UserProfile, WhoIsNode, WhoIsResponse};
use kithd::auth::WhoIsProvider;
use kithd::build_app;
use kithd::build_dispatcher;
use kithd::extractors::AppState;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use ulid::Ulid;

// ---------------------------------------------------------------------------
// Helper: build the AppState used by spawn_test_listener smoke tests.
// Only compiled when the `test-utils` feature is enabled.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-utils")]
fn make_state_for_listener(whois: MockWhoIs) -> (AppState<MockWhoIs>, tempfile::TempDir) {
    let store = Arc::new(Mutex::new(
        Store::open_in_memory().expect("in-memory store must open"),
    ));
    let (events_tx, _events_rx) = make_channel(64);
    let (blob_store, blob_dir) = make_blob_store();
    let dispatcher = Arc::new(build_dispatcher(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        OWNER_ID.to_string(),
    ));
    let state = AppState {
        ts: Arc::new(whois),
        store,
        owner_id: OWNER_ID.to_string(),
        owner_login: OWNER_LOGIN.to_string(),
        base_url: kithd::DEFAULT_BASE_URL.to_string(),
        events_tx,
        dispatcher,
        blob_store,
    };
    (state, blob_dir)
}

// ---------------------------------------------------------------------------
// Test 7: spawn_test_listener returns a valid loopback SocketAddr and the
// port is reachable via a plain TCP connect.
//
// NOTE: This test requires the `test-utils` feature:
//   cargo test -p kithd --features test-utils
// Without the feature, this test is compiled out and will not run.
//
// Oracle: a successful TcpStream::connect proves the OS assigned a real
// listening socket.  The addr must be 127.0.0.1 and the port must be
// non-zero (OS-assigned ephemeral port).  No TLS handshake or HTTP request
// is issued; the test is purely about socket binding.
// ---------------------------------------------------------------------------
#[cfg(feature = "test-utils")]
#[tokio::test]
async fn spawn_test_listener_binds_loopback_port() {
    let (state, _blob_dir) =
        make_state_for_listener(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let (addr, cert_der, handle) = kithd::spawn_test_listener(state)
        .await
        .expect("spawn_test_listener must succeed");

    // Oracle 1: addr must be 127.0.0.1 with a non-zero port.
    assert_eq!(
        addr.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "listener must bind to loopback"
    );
    assert_ne!(addr.port(), 0, "OS must assign a non-zero port");

    // Oracle 2: cert_der must be non-empty (a real DER-encoded certificate).
    assert!(!cert_der.is_empty(), "cert_der must be non-empty");

    // Oracle 3: a plain TCP connect to the returned address must succeed,
    // proving the listener socket is live.
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("TCP connect to spawn_test_listener must succeed");
    drop(tcp);

    handle.abort();
}

// ---------------------------------------------------------------------------
// Test double: MockWhoIs
//
// Returns a fixed WhoIsResponse for any address (Some variant), or an auth
// error (None variant).  The None path exercises the 500 / auth-failure path.
// ---------------------------------------------------------------------------

struct MockWhoIs(Option<WhoIsResponse>);

impl WhoIsProvider for MockWhoIs {
    fn whois(
        &self,
        _addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send {
        let result: Result<WhoIsResponse, AuthError> = match &self.0 {
            Some(r) => Ok(r.clone()),
            None => Err(AuthError::WhoIsFailed("test-mock-failure".into())),
        };
        async move { result }
    }
}

fn make_whois_resp(id: &str, login: &str) -> WhoIsResponse {
    WhoIsResponse {
        node: WhoIsNode {
            name: "test-node.tail12345.ts.net".into(),
        },
        user_profile: UserProfile {
            id: id.into(),
            login_name: login.into(),
            display_name: None,
        },
    }
}

// ---------------------------------------------------------------------------
// App factory
//
// Builds the full kithd Router with all 15 JMAP handlers registered, using
// MockWhoIs and an in-memory SQLite store.  `MockConnectInfo` provides the
// peer socket address that the Caller extractor requires.
// ---------------------------------------------------------------------------

fn make_blob_store() -> (std::sync::Arc<kith_attach::BlobStore>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("TempDir::new should succeed");
    let store = std::sync::Arc::new(kith_attach::BlobStore::new(dir.path()));
    store.init().expect("blob store init must succeed");
    (store, dir)
}

const OWNER_ID: &str = "uid-owner-e2e";
const OWNER_LOGIN: &str = "owner@e2e.example.com";

fn make_full_app(whois: MockWhoIs) -> (Router, tempfile::TempDir) {
    let store = Arc::new(Mutex::new(
        Store::open_in_memory().expect("in-memory store must open"),
    ));
    let (events_tx, _events_rx) = make_channel(64);
    let (blob_store, blob_dir) = make_blob_store();
    let dispatcher = Arc::new(build_dispatcher(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        OWNER_ID.to_string(),
    ));

    let state = AppState {
        ts: Arc::new(whois),
        store,
        owner_id: OWNER_ID.to_string(),
        owner_login: OWNER_LOGIN.to_string(),
        base_url: kithd::DEFAULT_BASE_URL.to_string(),
        events_tx,
        dispatcher,
        blob_store,
    };

    (
        build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999)))),
        blob_dir,
    )
}

// ---------------------------------------------------------------------------
// App factory variant: returns both the Router and the store Arc so tests
// can read state counters independently of the request path.
//
// Separate from make_full_app because the existing helper does not expose
// the store handle; adding a return value would be a breaking change to
// existing test call sites.
// ---------------------------------------------------------------------------

fn make_app_with_store(whois: MockWhoIs) -> (Router, Arc<Mutex<Store>>, tempfile::TempDir) {
    let store = Arc::new(Mutex::new(
        Store::open_in_memory().expect("in-memory store must open"),
    ));
    let (events_tx, _events_rx) = make_channel(64);
    let (blob_store, blob_dir) = make_blob_store();
    let dispatcher = Arc::new(build_dispatcher(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        OWNER_ID.to_string(),
    ));
    let state = AppState {
        ts: Arc::new(whois),
        store: Arc::clone(&store),
        owner_id: OWNER_ID.to_string(),
        owner_login: OWNER_LOGIN.to_string(),
        base_url: kithd::DEFAULT_BASE_URL.to_string(),
        events_tx,
        dispatcher,
        blob_store,
    };
    let app = build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
    (app, store, blob_dir)
}

// ---------------------------------------------------------------------------
// Helper: read the full response body as a String.
// ---------------------------------------------------------------------------

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("body must be readable");
    String::from_utf8(bytes.to_vec()).expect("body must be valid UTF-8")
}

// ---------------------------------------------------------------------------
// Test 1: GET /.well-known/jmap → 200 with JMAP Session object
//
// Oracle: RFC 8620 §2 — the Session object MUST contain a "capabilities"
// field.  The kith capability MUST be listed as "urn:ietf:params:jmap:chat".
// The response MUST have HTTP 200.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn e2e_session_endpoint_returns_kith_capability() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "session endpoint must return 200"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("session response must be valid JSON");

    // RFC 8620 §2: "capabilities" field is required.
    assert!(
        json.get("capabilities").is_some(),
        "session object must have 'capabilities' field; body: {body}"
    );

    // Kith capability must be present (RFC 8620 §2 requires all server
    // capabilities to be listed; "urn:ietf:params:jmap:chat" is the kith-specific one).
    assert!(
        json["capabilities"]
            .get("urn:ietf:params:jmap:chat")
            .is_some(),
        "capabilities must include 'urn:ietf:params:jmap:chat'; body: {body}"
    );

    // RFC 8620 §2: apiUrl, accounts, primaryAccounts, username are all required.
    assert!(
        json.get("apiUrl").is_some(),
        "session object must have 'apiUrl'; body: {body}"
    );
    assert!(
        json.get("accounts").is_some(),
        "session object must have 'accounts'; body: {body}"
    );
    assert!(
        json.get("primaryAccounts").is_some(),
        "session object must have 'primaryAccounts'; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: POST /jmap/api with Contact/get (ids=null) → 200 with valid response
//
// Oracle: RFC 8620 §3.4 — the JMAP response envelope MUST contain
// "methodResponses" with at least one entry.  The first entry's method name
// (index 0 in the invocation tuple) MUST equal "ChatContact/get".
// HTTP status MUST be 200 for any method-level result (RFC 8620 §3).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn e2e_contact_get_returns_method_response() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    // Manually constructed request from the RFC 8620 §3.3 format spec.
    // Not derived from any implementation output.
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["ChatContact/get", {"accountId": "a-self", "ids": null}, "c0"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "JMAP API endpoint must return 200 for method-level responses"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    // RFC 8620 §3.4: "methodResponses" is an array of Invocation tuples.
    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(
        !method_responses.is_empty(),
        "methodResponses must have at least one entry; body: {body}"
    );

    // RFC 8620 §3.3: each Invocation is [name, arguments, methodCallId].
    // The name MUST be "ChatContact/get" — the same method we called.
    let first_response = &method_responses[0];
    assert_eq!(
        first_response[0].as_str(),
        Some("ChatContact/get"),
        "first response method name must be 'Contact/get'; body: {body}"
    );

    // Call ID must be echoed verbatim (RFC 8620 §3.3).
    assert_eq!(
        first_response[2].as_str(),
        Some("c0"),
        "call ID must be echoed as 'c0'; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: POST /jmap/api with unknown method → 200 with "unknownMethod" error
//
// Oracle: RFC 8620 §7.1 — when a method is not recognized, the server MUST
// return an error Invocation with type "unknownMethod".  The outer HTTP
// status is still 200 (errors are carried inside methodResponses, not as
// HTTP error codes).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn e2e_unknown_method_returns_unknownmethod_error() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["NoSuchMethod/foo", {"accountId": "a-self"}, "c1"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // RFC 8620 §3: method-level errors still produce HTTP 200.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "unknown method must still produce HTTP 200"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(
        !method_responses.is_empty(),
        "methodResponses must not be empty; body: {body}"
    );

    // RFC 8620 §3.6.2: the method name is preserved in error invocations.
    assert_eq!(
        method_responses[0][0].as_str(),
        Some("NoSuchMethod/foo"),
        "error invocation must echo the original method name; body: {body}"
    );

    // RFC 8620 §7.1: the error type in the args must be "unknownMethod".
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("unknownMethod"),
        "error type must be 'unknownMethod'; body: {body}"
    );

    // RFC 8620 §3.3: call ID must be echoed verbatim.
    assert_eq!(
        method_responses[0][2].as_str(),
        Some("c1"),
        "call ID must be echoed as 'c1'; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Caller with unknown identity → 401 Unauthorized
//
// Oracle: The HTTP spec (RFC 9110 §15.5.2) and the kith authorization model:
// a caller whose Tailscale identity is neither the owner nor a permitted
// contact must receive HTTP 401.  The response body must NOT contain any
// PII (no user ID, no login name).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn e2e_unauthorized_caller_gets_401() {
    // Stranger is not the owner and not in contacts → must be rejected.
    let stranger_id = "uid-stranger-unknown";
    let stranger_login = "stranger@unknown.example.com";
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(
        stranger_id,
        stranger_login,
    ))));

    // The route doesn't matter — auth runs before dispatch on every request.
    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unknown caller must receive 401"
    );

    let body = body_string(resp).await;

    // PII must not appear in the error response (defensive security rule).
    assert!(
        !body.contains(stranger_id),
        "user_id must not appear in 401 body; body: {body}"
    );
    assert!(
        !body.contains(stranger_login),
        "login_name must not appear in 401 body; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Peer calls an owner-only method → "forbidden" error in response
//
// Oracle: kith authorization model + RFC 8620 §7.1 —
// a caller with Role::Peer who invokes an owner-only method (e.g. Contact/get)
// MUST receive a method-level error with type "forbidden".
// HTTP status is still 200 (errors live in methodResponses per RFC 8620 §3).
// The peer must first be admitted (i.e. in contacts, not blocked); if not,
// the test would hit 401 and never reach the dispatcher — that is a different
// path covered by e2e_unauthorized_caller_gets_401.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_calls_owner_method_forbidden() {
    const PEER_ID: &str = "uid-peer-bob";
    const PEER_LOGIN: &str = "bob@peer.example.com";

    // Build the app and obtain the store so we can add a contact before
    // the request is dispatched.
    let (app, store, _blob_dir) =
        make_app_with_store(MockWhoIs(Some(make_whois_resp(PEER_ID, PEER_LOGIN))));

    // Register the peer as an unblocked contact so Role::Peer is assigned by the
    // extractor.  Without this the extractor returns 401 and the test never
    // reaches the dispatcher role check.
    // unwrap: test-only store with correct schema; cannot fail.
    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(PEER_ID, PEER_LOGIN, "bob-kith.tail.ts.net", None, 1_000_000)
        .expect("upsert must succeed for a correctly-opened in-memory store");

    // Contact/get requires Role::Owner.  A Role::Peer caller must receive
    // "forbidden", not a 401 (auth already passed).
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["ChatContact/get", {"accountId": "a-self", "ids": null}, "p0"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // RFC 8620 §3: method-level errors still produce HTTP 200.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "method-level forbidden must still produce HTTP 200"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(
        !method_responses.is_empty(),
        "methodResponses must not be empty; body: {body}"
    );

    // RFC 8620 §3.3: method name is echoed in error invocations.
    assert_eq!(
        method_responses[0][0].as_str(),
        Some("ChatContact/get"),
        "error invocation must echo the original method name; body: {body}"
    );

    // Oracle: dispatcher role check produces "forbidden" for peer→owner call.
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("forbidden"),
        "error type must be 'forbidden' for a peer calling an owner method; body: {body}"
    );

    // RFC 8620 §3.3: call ID must be echoed verbatim.
    assert_eq!(
        method_responses[0][2].as_str(),
        Some("p0"),
        "call ID must be echoed as 'p0'; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Test 5b: Peer calls ChatContact/queryChanges → "forbidden"
//
// Oracle: kith authorization model + RFC 8620 §7.1 — ChatContact/queryChanges
// is an owner-only method; a Role::Peer caller must receive "forbidden".
// This is a separate test from peer_calls_owner_method_forbidden to ensure
// this specific method is covered by the peer-rejection matrix.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_calls_chatcontact_querychanges_forbidden() {
    const PEER_ID: &str = "uid-peer-qc";
    const PEER_LOGIN: &str = "qc@peer.example.com";

    let (app, store, _blob_dir) =
        make_app_with_store(MockWhoIs(Some(make_whois_resp(PEER_ID, PEER_LOGIN))));
    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(PEER_ID, PEER_LOGIN, "qc-kith.tail.ts.net", None, 1_000_000)
        .expect("upsert must succeed");

    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["ChatContact/queryChanges", {"accountId": "a-self", "sinceQueryState": "s-0"}, "qc0"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");
    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(!method_responses.is_empty());
    assert_eq!(
        method_responses[0][0].as_str(),
        Some("ChatContact/queryChanges"),
        "error invocation must echo the method name; body: {body}"
    );
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("forbidden"),
        "peer calling ChatContact/queryChanges must get forbidden; body: {body}"
    );
    assert_eq!(method_responses[0][2].as_str(), Some("qc0"));
}

// ---------------------------------------------------------------------------
// Test 6: Peer/deliver with senderUserId != WhoIs identity → rejected
//
// Oracle: kith authorization model §Defensive Input Handling —
// senderUserId MUST equal the WhoIs-verified caller identity BEFORE
// any database write.  The independent oracle is the message state counter:
// if counter is unchanged after the request, no write occurred.
//
// Error type oracle: DeliverHandler step 3 maps this mismatch to
// "invalidArguments" (specified in kith-architecture.md §Defensive Input).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_deliver_sender_mismatch_rejected() {
    const PEER_ID: &str = "uid-peer-carol";
    const PEER_LOGIN: &str = "carol@peer.example.com";

    let (app, store, _blob_dir) =
        make_app_with_store(MockWhoIs(Some(make_whois_resp(PEER_ID, PEER_LOGIN))));

    // Register peer as a contact so the Caller extractor grants Role::Peer.
    // Without this the request gets a 401 before reaching DeliverHandler.
    // unwrap: test-only store with correct schema; cannot fail.
    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(
            PEER_ID,
            PEER_LOGIN,
            "carol-kith.tail.ts.net",
            None,
            1_000_000,
        )
        .expect("upsert must succeed for a correctly-opened in-memory store");

    // Read the message state counter BEFORE the request.
    // This is the independent oracle: if it equals the value after, no write occurred.
    // unwrap: store is freshly opened; get_state cannot fail.
    let state_before = store
        .lock()
        .expect("store lock must not be poisoned")
        .messages()
        .get_state()
        .expect("get_state must succeed on a fresh in-memory store");

    // Build a Peer/deliver request where senderUserId differs from
    // the WhoIs identity (PEER_ID).  The chatId is derived from the correct
    // participants so any failure is solely due to the sender mismatch, not a
    // chatId issue.  (DeliverHandler validates sender first, then chatId.)
    let chat_id = "test-chat-sender-mismatch".to_string();
    // unwrap: Ulid::new() cannot fail; to_string() cannot fail.
    let msg_id = Ulid::new().to_string();
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Peer/deliver", {
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": chat_id,
                "senderUserId": "uid-evil-impersonator",
                "body": "injected message",
                "bodyType": "text/plain",
                "sentAt": "2026-01-01T00:00:00Z"
            }
        }, "d0"]]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // RFC 8620 §3: method-level errors always produce HTTP 200.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "method-level error must produce HTTP 200"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(
        !method_responses.is_empty(),
        "methodResponses must not be empty; body: {body}"
    );

    // Oracle: DeliverHandler step 3 — sender mismatch → "invalidArguments".
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("invalidArguments"),
        "senderUserId mismatch must produce 'invalidArguments'; body: {body}"
    );

    // Oracle: state counter must be identical to the pre-request value, proving
    // no database write occurred.  The state counter is advanced atomically with
    // each message INSERT; an unchanged counter means zero writes.
    let state_after = store
        .lock()
        .expect("store lock must not be poisoned after oneshot")
        .messages()
        .get_state()
        .expect("get_state must succeed after request");

    assert_eq!(
        state_before, state_after,
        "message state counter must be unchanged after a rejected Peer/deliver \
         (before={state_before}, after={state_after})"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Peer/deliver where chatId belongs to a different contact → rejected
//
// Oracle: the chatId-contact ownership check in DeliverHandler rejects a
// peer that tries to inject a message into a chat that belongs to a different
// contact.  This test exercises the full HTTP → Caller extractor →
// _caller_identity → DeliverHandler path, not just the handler in isolation.
//
// Independent oracle: the message state counter must be unchanged, proving
// no database write occurred before the check fired.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_deliver_chatid_contact_mismatch_rejected() {
    const PEER_ALICE_ID: &str = "uid-peer-alice-e2e";
    const PEER_ALICE_LOGIN: &str = "alice@peer.example.com";
    const PEER_BOB_ID: &str = "uid-peer-bob-e2e";
    const PEER_BOB_LOGIN: &str = "bob@peer.example.com";

    // App is configured to identify every incoming connection as Alice.
    let (app, store, _blob_dir) = make_app_with_store(MockWhoIs(Some(make_whois_resp(
        PEER_ALICE_ID,
        PEER_ALICE_LOGIN,
    ))));

    // Register both Alice and Bob as contacts so Role::Peer is assigned.
    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(
            PEER_ALICE_ID,
            PEER_ALICE_LOGIN,
            "alice-kith.tail.ts.net",
            None,
            1_000_000,
        )
        .expect("upsert alice must succeed");

    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(
            PEER_BOB_ID,
            PEER_BOB_LOGIN,
            "bob-kith.tail.ts.net",
            None,
            1_000_001,
        )
        .expect("upsert bob must succeed");

    // Pre-create a direct chat belonging to Bob (contact_id = PEER_BOB_ID).
    let bob_chat_id = "chat-owned-by-bob-e2e";
    store
        .lock()
        .expect("store lock must not be poisoned")
        .chats()
        .create(bob_chat_id, "direct", Some(PEER_BOB_ID), 1_000_002)
        .expect("pre-create Bob's chat must succeed");

    // Read message state counter before the request.
    let state_before = store
        .lock()
        .expect("store lock must not be poisoned")
        .messages()
        .get_state()
        .expect("get_state must succeed on a fresh store");

    // Alice attempts to deliver into Bob's chat.
    let msg_id = ulid::Ulid::new().to_string();
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Peer/deliver", {
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": bob_chat_id,
                "senderUserId": PEER_ALICE_ID,
                "body": "Alice injecting into Bob's chat",
                "bodyType": "text/plain",
                "sentAt": "2026-01-01T00:00:00Z"
            }
        }, "d0"]]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // RFC 8620 §3: method-level errors always produce HTTP 200.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "method-level error must produce HTTP 200"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(
        !method_responses.is_empty(),
        "methodResponses must not be empty; body: {body}"
    );

    // Oracle: chatId-contact mismatch → "invalidArguments".
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("invalidArguments"),
        "chatId-contact mismatch must produce 'invalidArguments'; body: {body}"
    );

    // Oracle: state counter must be unchanged — no message was written.
    let state_after = store
        .lock()
        .expect("store lock must not be poisoned after oneshot")
        .messages()
        .get_state()
        .expect("get_state must succeed after request");

    assert_eq!(
        state_before, state_after,
        "message state counter must be unchanged after chatId mismatch rejection \
         (before={state_before}, after={state_after})"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Peer/receipt from wrong contact returns notFound
//
// Oracle: ReceiptHandler step i — only the chat's contact_id may send receipts
// for messages in that conversation.  A peer who is a known contact but whose
// user_id does not match chat.contact_id must receive notFound (not forbidden,
// to avoid leaking whether the message_id exists).
//
// Independent oracle: message state counter must be unchanged, proving the
// delivery_state was not updated before the check fired.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_receipt_wrong_contact_returns_not_found() {
    const PEER_ALICE_ID: &str = "uid-peer-alice-receipt";
    const PEER_ALICE_LOGIN: &str = "alice@receipt.example.com";
    const PEER_BOB_ID: &str = "uid-peer-bob-receipt";
    const PEER_BOB_LOGIN: &str = "bob@receipt.example.com";

    // App identifies every incoming connection as Alice.
    let (app, store, _blob_dir) = make_app_with_store(MockWhoIs(Some(make_whois_resp(
        PEER_ALICE_ID,
        PEER_ALICE_LOGIN,
    ))));

    // Register Alice as a contact so the Caller extractor grants Role::Peer.
    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(
            PEER_ALICE_ID,
            PEER_ALICE_LOGIN,
            "alice-kith.tail.ts.net",
            None,
            1_000_000,
        )
        .expect("upsert alice must succeed");

    // Register Bob as a contact and create Bob's outbound chat.
    store
        .lock()
        .expect("store lock must not be poisoned")
        .contacts()
        .upsert(
            PEER_BOB_ID,
            PEER_BOB_LOGIN,
            "bob-kith.tail.ts.net",
            None,
            1_000_001,
        )
        .expect("upsert bob must succeed");

    let bob_chat_id = "chat-for-bob-receipt-test";
    store
        .lock()
        .expect("store lock must not be poisoned")
        .chats()
        .create(bob_chat_id, "direct", Some(PEER_BOB_ID), 1_000_002)
        .expect("create Bob's chat must succeed");

    // Insert an outbound message in Bob's chat.  This is the message Alice will
    // attempt to send a receipt for.  sender_user_id = 'self' and delivery_state
    // = 'pending' so ReceiptHandler reaches the contact_id check.
    let msg_id = Ulid::new().to_string();
    {
        let guard = store.lock().expect("store lock must not be poisoned");
        guard
            .insert_outbound_message(&kith_store::OutboundMessageParams {
                id: &msg_id,
                chat_id: bob_chat_id,
                sender_user_id: OWNER_ID,
                body: "hello bob",
                body_type: "text/plain",
                sent_at_peer: None,
                created_at_unix: 1_000_003,
                reply_to: None,
                attachments: &[],
                mentions: &[],
                outbox_peers: &[(PEER_BOB_ID, "bob-kith.tail.ts.net")],
                thread_root_id: None,
                sender_expires_at: None,
                burn_on_read: false,
                broadcast_mentions: &[],
            })
            .expect("insert outbound message must succeed");
    }

    // Read the message state counter BEFORE the receipt request.
    let state_before = store
        .lock()
        .expect("store lock must not be poisoned")
        .messages()
        .get_state()
        .expect("get_state must succeed");

    // Alice sends Peer/receipt claiming to have received the message in Bob's chat.
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Peer/receipt", {
            "accountId": "a-self",
            "messageId": msg_id,
            "kind": "delivered",
            "at": "2026-01-01T00:00:00Z"
        }, "r0"]]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // RFC 8620 §3: method-level errors always produce HTTP 200.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "method-level error must produce HTTP 200"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(
        !method_responses.is_empty(),
        "methodResponses must not be empty; body: {body}"
    );

    // Oracle: ReceiptHandler step i — wrong contact_id → notFound.
    // notFound (not forbidden) to avoid leaking whether the message_id exists.
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("notFound"),
        "wrong contact sending receipt must produce 'notFound'; body: {body}"
    );

    // Oracle: state counter must be unchanged — delivery_state was not updated.
    let state_after = store
        .lock()
        .expect("store lock must not be poisoned after oneshot")
        .messages()
        .get_state()
        .expect("get_state must succeed after request");

    assert_eq!(
        state_before, state_after,
        "message state counter must be unchanged after rejected Peer/receipt \
         (before={state_before}, after={state_after})"
    );
}

// ---------------------------------------------------------------------------
// Test 9: Peer/receipt for a nonexistent message returns notFound
//
// Oracle: ReceiptHandler step f — message lookup returns None → notFound.
// A peer who is a valid contact must not learn whether an arbitrary message_id
// exists or belongs to a different conversation.
//
// Independent oracle: state counter must be unchanged (no write occurred).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn peer_receipt_nonexistent_message_returns_not_found() {
    const PEER_ID: &str = "uid-peer-dana-receipt";
    const PEER_LOGIN: &str = "dana@receipt.example.com";

    let (app, store, _blob_dir) =
        make_app_with_store(MockWhoIs(Some(make_whois_resp(PEER_ID, PEER_LOGIN))));

    // Register peer as a contact so the Caller extractor grants Role::Peer.
    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(
            PEER_ID,
            PEER_LOGIN,
            "dana-kith.tail.ts.net",
            None,
            1_000_000,
        )
        .expect("upsert must succeed");

    let state_before = store
        .lock()
        .expect("store lock must not be poisoned")
        .messages()
        .get_state()
        .expect("get_state must succeed");

    // Send receipt for a message_id that does not exist in the store.
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Peer/receipt", {
            "accountId": "a-self",
            "messageId": "01JQNONEXISTENTMESSAGEID0001",
            "kind": "read",
            "at": "2026-01-01T00:00:00Z"
        }, "r1"]]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "method-level error must produce HTTP 200"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(
        !method_responses.is_empty(),
        "methodResponses must not be empty; body: {body}"
    );

    // Oracle: ReceiptHandler step f — nonexistent message_id → notFound.
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("notFound"),
        "receipt for nonexistent message must produce 'notFound'; body: {body}"
    );

    // Oracle: state counter unchanged — no write occurred.
    let state_after = store
        .lock()
        .expect("store lock must not be poisoned after oneshot")
        .messages()
        .get_state()
        .expect("get_state must succeed after request");

    assert_eq!(
        state_before, state_after,
        "message state counter must be unchanged after rejected Peer/receipt \
         (before={state_before}, after={state_after})"
    );
}

// ---------------------------------------------------------------------------
// Test: PeerHttpClient::new() connects to a self-signed certificate.
//
// Oracle: kithd generates self-signed certs via rcgen (load_or_generate_cert).
// PeerHttpClient::new() must use TailnetCertVerifier (accept any cert) rather
// than WebPKI roots, which would reject a self-signed cert.  This test fails
// if PeerHttpClient::new() is ever changed back to .with_webpki_roots().
//
// Only compiled with --features test-utils (requires spawn_test_listener).
// ---------------------------------------------------------------------------
#[cfg(feature = "test-utils")]
#[tokio::test]
async fn peer_http_client_new_accepts_self_signed_cert() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    kithd::allow_loopback_for_tests();

    // The receiver's MockWhoIs returns the peer identity so all incoming
    // requests are classified as Peer role (not Owner, not unauthorized).
    const PEER_ID: &str = "uid-peer-webpki-regression";
    const PEER_LOGIN: &str = "peer@webpki-regression.example.com";

    // Build the state manually so we can upsert the peer contact before
    // handing the store off to spawn_test_listener (which takes ownership of
    // the AppState).  Without a contacts row the Caller extractor returns 401
    // before the request reaches DeliverHandler.
    let store = Arc::new(Mutex::new(
        Store::open_in_memory().expect("in-memory store must open"),
    ));
    store
        .lock()
        .expect("store lock must not be poisoned in test setup")
        .contacts()
        .upsert(
            PEER_ID,
            PEER_LOGIN,
            "peer-kith.tail.ts.net",
            None,
            1_000_000,
        )
        .expect("upsert must succeed for a correctly-opened in-memory store");
    let (events_tx, _events_rx) = make_channel(64);
    let (blob_store, _blob_dir) = make_blob_store();
    let dispatcher = Arc::new(build_dispatcher(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        OWNER_ID.to_string(),
    ));
    let state = AppState {
        ts: Arc::new(MockWhoIs(Some(make_whois_resp(PEER_ID, PEER_LOGIN)))),
        store,
        owner_id: OWNER_ID.to_string(),
        owner_login: OWNER_LOGIN.to_string(),
        base_url: kithd::DEFAULT_BASE_URL.to_string(),
        events_tx,
        dispatcher,
        blob_store,
    };
    let (addr, _cert_der, handle) = kithd::spawn_test_listener(state)
        .await
        .expect("spawn_test_listener must succeed");

    // Build a valid Peer/deliver request.  The sender identity matches PEER_ID
    // so the senderUserId check in DeliverHandler passes.
    let msg_id = Ulid::new().to_string();
    let jmap_request = kith_peer::build_peer_deliver_request(
        &msg_id,
        "regression-chat-01",
        PEER_ID,
        "regression: PeerHttpClient::new must accept self-signed certs",
        "text/plain",
        "2026-04-24T00:00:00Z",
        None,
        &[],
        &[],
    );

    // Use PeerHttpClient::new() — NOT new_with_root_cert — to prove the
    // production path works against a self-signed cert.
    let client = kith_peer::PeerHttpClient::new();
    let url = format!("https://127.0.0.1:{}/jmap/api", addr.port());
    let result = client.deliver(&url, jmap_request).await;

    handle.abort();

    assert!(
        result.is_ok(),
        "PeerHttpClient::new() must accept self-signed cert from kithd; \
         got: {:?}",
        result.err()
    );
}

// ===========================================================================
// Session endpoint tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Session: capabilities contains urn:ietf:params:jmap:core
//
// Oracle: RFC 8620 §2 — the Session object MUST advertise
// "urn:ietf:params:jmap:core" in the capabilities map.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn session_contains_core_capability() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("session response must be valid JSON");

    assert!(
        json["capabilities"]
            .get("urn:ietf:params:jmap:core")
            .is_some(),
        "capabilities must include 'urn:ietf:params:jmap:core'; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Session: account with correct ID "a-self"
//
// Oracle: kith session design — the only account is "a-self".
// ---------------------------------------------------------------------------
#[tokio::test]
async fn session_contains_account_a_self() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("session response must be valid JSON");

    assert!(
        json["accounts"].get("a-self").is_some(),
        "accounts must contain 'a-self'; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Session: supportedBodyTypes includes all three types
//
// Oracle: kith spec — supportedBodyTypes MUST contain text/plain,
// text/markdown, and application/jmap-chat-rich.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn session_supported_body_types() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("session response must be valid JSON");

    let chat_cap = &json["capabilities"]["urn:ietf:params:jmap:chat"];
    let supported = chat_cap["supportedBodyTypes"]
        .as_array()
        .expect("supportedBodyTypes must be an array");

    let types: Vec<&str> = supported.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        types.contains(&"text/plain"),
        "supportedBodyTypes must include text/plain; got: {types:?}"
    );
    assert!(
        types.contains(&"text/markdown"),
        "supportedBodyTypes must include text/markdown; got: {types:?}"
    );
    assert!(
        types.contains(&"application/jmap-chat-rich"),
        "supportedBodyTypes must include application/jmap-chat-rich; got: {types:?}"
    );
}

// ---------------------------------------------------------------------------
// Session: maxBodyBytes matches MAX_BODY_BYTES constant (65536)
//
// Oracle: kith spec — maxBodyBytes is 65536 (64 KiB).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn session_max_body_bytes() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("session response must be valid JSON");

    let chat_cap = &json["capabilities"]["urn:ietf:params:jmap:chat"];
    assert_eq!(
        chat_cap["maxBodyBytes"].as_u64(),
        Some(65_536),
        "maxBodyBytes must be 65536; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// Session: maxAttachmentBytes matches MAX_ATTACHMENT_BYTES (104857600)
//
// Oracle: kith spec — maxAttachmentBytes is 104857600 (100 MiB).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn session_max_attachment_bytes() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("session response must be valid JSON");

    let chat_cap = &json["capabilities"]["urn:ietf:params:jmap:chat"];
    assert_eq!(
        chat_cap["maxAttachmentBytes"].as_u64(),
        Some(104_857_600),
        "maxAttachmentBytes must be 104857600; body: {body}"
    );
}

// ===========================================================================
// JMAP API endpoint tests
// ===========================================================================

// ---------------------------------------------------------------------------
// JMAP API: valid request returns 200
//
// Oracle: RFC 8620 §3 — a well-formed JMAP request must always return HTTP 200.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_api_valid_request_returns_200() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["Chat/get", {"accountId": "a-self", "ids": null}, "c0"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// JMAP API: invalid JSON body returns error
//
// Oracle: axum's Json extractor rejects non-JSON with an HTTP error status
// (422 Unprocessable Entity or 400 Bad Request depending on the failure mode).
// The key assertion is that the status is NOT 200.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_api_invalid_json_returns_error() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from("this is not json {{{"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // axum returns 422 for malformed JSON when Content-Type is correct
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "invalid JSON body must not return 200"
    );
    assert!(
        resp.status().is_client_error(),
        "invalid JSON must return a 4xx error; got: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// JMAP API: multiple method calls returns multiple responses
//
// Oracle: RFC 8620 §3.4 — each method call in the request produces one
// corresponding entry in methodResponses.  Two calls must yield two responses.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_api_multiple_method_calls() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["Chat/get", {"accountId": "a-self", "ids": null}, "c0"],
            ["ChatContact/get", {"accountId": "a-self", "ids": null}, "c1"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert_eq!(
        method_responses.len(),
        2,
        "two method calls must produce two responses; body: {body}"
    );
    assert_eq!(method_responses[0][2].as_str(), Some("c0"));
    assert_eq!(method_responses[1][2].as_str(), Some("c1"));
}

// ---------------------------------------------------------------------------
// JMAP API: Peer/deliver from peer succeeds
//
// Oracle: A known peer calling Peer/deliver with correct senderUserId
// produces either a success response or an invalidArguments error related to
// chatId (not "unknownMethod" or "forbidden").  The key check is that the
// dispatcher routes Peer/deliver to the peer handler.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_api_peer_deliver_routed_correctly() {
    const PEER_ID: &str = "uid-peer-route";
    const PEER_LOGIN: &str = "route@peer.example.com";

    let (app, store, _blob_dir) =
        make_app_with_store(MockWhoIs(Some(make_whois_resp(PEER_ID, PEER_LOGIN))));

    store
        .lock()
        .expect("store lock must not be poisoned")
        .contacts()
        .upsert(PEER_ID, PEER_LOGIN, "route-kith.tail.ts.net", None, 1_000_000)
        .expect("upsert must succeed");

    let msg_id = Ulid::new().to_string();
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Peer/deliver", {
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": "any-chat-id",
                "senderUserId": PEER_ID,
                "body": "hello",
                "bodyType": "text/plain",
                "sentAt": "2026-01-01T00:00:00Z"
            }
        }, "d0"]]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(!method_responses.is_empty());

    // Must not be unknownMethod or forbidden — the method is routed to DeliverHandler.
    let error_type = method_responses[0][1]["type"].as_str();
    assert_ne!(
        error_type,
        Some("unknownMethod"),
        "Peer/deliver must not return unknownMethod; body: {body}"
    );
    assert_ne!(
        error_type,
        Some("forbidden"),
        "Peer/deliver from a peer must not return forbidden; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// JMAP API: owner calling peer method (Peer/deliver) returns forbidden
//
// Oracle: kith authorization model — owner calling a peer-only method must
// receive "forbidden" error in methodResponses.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_api_owner_calls_peer_method_forbidden() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let msg_id = Ulid::new().to_string();
    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Peer/deliver", {
            "accountId": "a-self",
            "message": {
                "id": msg_id,
                "chatId": "owner-chat",
                "senderUserId": OWNER_ID,
                "body": "owner attempting peer method",
                "bodyType": "text/plain",
                "sentAt": "2026-01-01T00:00:00Z"
            }
        }, "o0"]]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("jmap response must be valid JSON");

    let method_responses = json["methodResponses"]
        .as_array()
        .expect("methodResponses must be an array");
    assert!(!method_responses.is_empty());
    assert_eq!(
        method_responses[0][1]["type"].as_str(),
        Some("forbidden"),
        "owner calling Peer/deliver must get forbidden; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// JMAP API: missing content-type returns error
//
// Oracle: axum's Json extractor requires Content-Type: application/json.
// A request without it returns 415 Unsupported Media Type.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_api_missing_content_type_returns_error() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["Chat/get", {"accountId": "a-self", "ids": null}, "c0"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        // No content-type header
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "missing content-type must return a 4xx error; got: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// JMAP API: empty request body returns error
//
// Oracle: an empty body is not valid JSON — axum rejects it before the
// handler runs.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_api_empty_body_returns_error() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "empty body must return a 4xx error; got: {}",
        resp.status()
    );
}

// ===========================================================================
// Blob endpoint tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Blob upload: small blob returns blobId
//
// Oracle: RFC 8620 §6.1 — a successful upload returns 201 with blobId, size,
// and type fields.  SHA-256 of b"test-blob" computed independently:
// printf 'test-blob' | sha256sum → 7e1ae3f38...
// ---------------------------------------------------------------------------
#[tokio::test]
async fn blob_upload_returns_blob_id() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let payload = b"test-blob";

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/upload/a-self")
        .header("content-type", "text/plain")
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "blob upload must return 201 Created"
    );

    let body = body_string(resp).await;
    let json: serde_json::Value =
        serde_json::from_str(&body).expect("upload response must be valid JSON");

    let blob_id = json["blobId"].as_str().expect("blobId must be a string");
    assert!(!blob_id.is_empty(), "blobId must be non-empty");
    assert_eq!(json["size"].as_u64(), Some(9));
}

// ---------------------------------------------------------------------------
// Blob download: uploaded blob is downloadable
//
// Oracle: a blob uploaded via POST /jmap/upload must be retrievable at
// GET /jmap/download/{accountId}/{blobId}/{name} with the same content.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn blob_upload_then_download() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let payload = b"roundtrip-payload";

    // Upload
    let upload_req = Request::builder()
        .method("POST")
        .uri("/jmap/upload/a-self")
        .header("content-type", "application/octet-stream")
        .body(Body::from(payload.to_vec()))
        .unwrap();

    let upload_resp = app.clone().oneshot(upload_req).await.unwrap();
    assert_eq!(upload_resp.status(), StatusCode::CREATED);

    let upload_body = body_string(upload_resp).await;
    let upload_json: serde_json::Value =
        serde_json::from_str(&upload_body).expect("upload response must be valid JSON");
    let blob_id = upload_json["blobId"]
        .as_str()
        .expect("blobId must be present")
        .to_string();

    // Download
    let download_req = Request::builder()
        .method("GET")
        .uri(format!("/jmap/download/a-self/{blob_id}/file.bin"))
        .body(Body::empty())
        .unwrap();

    let download_resp = app.oneshot(download_req).await.unwrap();
    assert_eq!(
        download_resp.status(),
        StatusCode::OK,
        "download of uploaded blob must return 200"
    );

    let body_bytes = axum::body::to_bytes(download_resp.into_body(), 1024 * 1024)
        .await
        .expect("download body must be readable");
    assert_eq!(
        body_bytes.as_ref(),
        payload,
        "downloaded bytes must match uploaded payload"
    );
}

// ---------------------------------------------------------------------------
// Blob download: nonexistent blobId returns 404
//
// Oracle: a blobId that was never uploaded must return 404.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn blob_download_nonexistent_returns_404() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    // Use a validly-formatted but non-existent blob ID (26 uppercase alphanumeric chars = ULID format)
    let fake_blob_id = "01JQFAKE0000000000000FAKE";
    let req = Request::builder()
        .method("GET")
        .uri(format!("/jmap/download/a-self/{fake_blob_id}/file.bin"))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "download of nonexistent blobId must return 404"
    );
}

// ---------------------------------------------------------------------------
// Blob upload: wrong accountId returns error
//
// Oracle: account_id must match "a-self" or the owner_id; any other value
// returns 400.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn blob_upload_wrong_account_id_returns_400() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/upload/uid-somebody-else")
        .header("content-type", "application/octet-stream")
        .body(Body::from(b"data".to_vec()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "upload with wrong accountId must return 400"
    );
}

// ---------------------------------------------------------------------------
// Blob download: wrong accountId returns 400
//
// Oracle: download with an accountId that is neither owner_id nor "a-self"
// must return 400 before any disk I/O.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn blob_download_wrong_account_id_returns_400() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/jmap/download/uid-wrong/someblobid/file.bin")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "download with wrong accountId must return 400"
    );
}

// ===========================================================================
// SSE endpoint tests
// ===========================================================================

// ---------------------------------------------------------------------------
// SSE: returns text/event-stream content type
//
// Oracle: SSE spec — the Content-Type must be text/event-stream.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sse_returns_event_stream_content_type() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/jmap/events")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("text/event-stream"),
        "SSE endpoint must return text/event-stream content-type; got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// SSE: state change after message insert
//
// Oracle: inserting a message into the store must trigger a state-change event.
// We use the events_tx directly (the same channel the store layer uses) to
// simulate a state change and verify the SSE stream delivers it.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sse_delivers_state_change() {
    use kith_core::StateChange;

    let store = Arc::new(Mutex::new(
        Store::open_in_memory().expect("in-memory store must open"),
    ));
    let (events_tx, _events_rx) = kith_events::make_channel(64);
    let (blob_store, _blob_dir) = make_blob_store();
    let dispatcher = Arc::new(build_dispatcher(
        Arc::clone(&store),
        Arc::clone(&blob_store),
        OWNER_ID.to_string(),
    ));
    let state = kithd::extractors::AppState {
        ts: Arc::new(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN)))),
        store,
        owner_id: OWNER_ID.to_string(),
        owner_login: OWNER_LOGIN.to_string(),
        base_url: kithd::DEFAULT_BASE_URL.to_string(),
        events_tx: events_tx.clone(),
        dispatcher,
        blob_store,
    };
    let app = build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));

    // Send a state change event after the handler subscribes.
    tokio::spawn(async move {
        tokio::task::yield_now().await;
        let _ = events_tx.send(StateChange {
            type_name: "Message".to_string(),
            new_state: "s-1".to_string(),
        });
    });

    let req = Request::builder()
        .method("GET")
        .uri("/jmap/events?closeafter=state")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 4096)
        .await
        .expect("SSE body must be readable");
    let body = std::str::from_utf8(&body_bytes).expect("SSE body must be UTF-8");

    assert!(
        body.contains("event: state"),
        "SSE must contain a state event; body: {body:?}"
    );
    assert!(
        body.contains("Message"),
        "SSE state event must reference Message type; body: {body:?}"
    );
    assert!(
        body.contains("s-1"),
        "SSE state event must contain state token s-1; body: {body:?}"
    );
}

// ---------------------------------------------------------------------------
// SSE: unauthorized peer returns 401
//
// Oracle: a caller whose identity is neither owner nor in contacts must
// receive 401 from the Caller extractor, before reaching the events handler.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn sse_unauthorized_caller_returns_401() {
    let stranger_id = "uid-stranger-sse";
    let stranger_login = "stranger@sse.example.com";
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(
        stranger_id,
        stranger_login,
    ))));

    let req = Request::builder()
        .method("GET")
        .uri("/jmap/events")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unknown caller must receive 401 on SSE endpoint"
    );
}

// ===========================================================================
// Error handling tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Unknown path: request to unregistered path returns 200 (SPA fallback)
// or 404 for paths with file extensions.
//
// Oracle: the static_handler fallback serves index.html for SPA routes
// (no extension) and 404 for missing files with extensions.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn unknown_path_with_extension_returns_404() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    let req = Request::builder()
        .method("GET")
        .uri("/nonexistent/path.js")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "request to nonexistent static file must return 404"
    );
}

// ---------------------------------------------------------------------------
// Very large request body rejected
//
// Oracle: MAX_REQUEST_BYTES = 10 MiB (10_485_760 bytes).  The /jmap/api
// endpoint has a DefaultBodyLimit set to this value.  A request exceeding
// it must be rejected with 413 Payload Too Large.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn large_request_body_rejected() {
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(OWNER_ID, OWNER_LOGIN))));

    // Build a body exceeding 10 MiB.  We send 10 MiB + 1 byte.
    let oversized = vec![b'x'; 10 * 1024 * 1024 + 1];

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(oversized))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "request exceeding MAX_REQUEST_BYTES must return 413"
    );
}

// ---------------------------------------------------------------------------
// Missing authorization returns 401
//
// Oracle: a caller with a failing WhoIs lookup (simulated by MockWhoIs(None))
// results in a CallerRejection::Internal → 500.  A stranger (not in contacts
// and not owner) gets 401.  This test uses a stranger identity.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn missing_authorization_returns_401() {
    let stranger_id = "uid-stranger-auth";
    let stranger_login = "auth-stranger@example.com";
    let (app, _blob_dir) = make_full_app(MockWhoIs(Some(make_whois_resp(
        stranger_id,
        stranger_login,
    ))));

    let request_body = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["Chat/get", {"accountId": "a-self", "ids": null}, "c0"]
        ]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/jmap/api")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&request_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "stranger must receive 401 on /jmap/api"
    );
}
