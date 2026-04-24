/// Integration tests for static file serving at `/`.
///
/// Oracle: HTTP spec (RFC 9110) and rust-embed documentation.
/// Expected behaviour is derived from the spec and the known web asset
/// filenames — not from running the code under test.
///
/// Tested invariants:
///   1. GET /              → 200, Content-Type: text/html, body contains HTML
///   2. GET /index.html    → 200, Content-Type: text/html, body contains HTML
///   3. GET /style.css     → 200, Content-Type: text/css
///   4. GET /app.js        → 200, Content-Type: application/javascript or text/javascript
///   5. GET /nonexistent   → 200 SPA fallback (no extension → serve index.html)
///   6. GET /no.txt        → 404 Not Found (extension present, file absent)
///   7. GET /.well-known/jmap → 200 (JMAP route not shadowed by static handler)
///   8. GET /chat/v2.1/messages → 200 SPA fallback (dot in non-final segment, no extension on final segment)
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
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
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Constants — oracle values independent of the implementation
// ---------------------------------------------------------------------------

/// The owner identity used by MockWhoIs so that session_handler (on
/// /.well-known/jmap) classifies the caller as Owner and returns 200.
const OWNER_ID: &str = "uid-owner-static";
const OWNER_LOGIN: &str = "owner@static.example.com";

/// Fixed peer address supplied to MockConnectInfo.  The static handler does
/// not inspect ConnectInfo, but the Layer requires it to be present on the
/// Router so the Caller extractor on other routes does not panic.
const MOCK_ADDR: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
    19999,
);

// ---------------------------------------------------------------------------
// Test double: MockWhoIs
// ---------------------------------------------------------------------------

struct MockWhoIs(WhoIsResponse);

impl WhoIsProvider for MockWhoIs {
    fn whois(
        &self,
        _addr: SocketAddr,
    ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send {
        let result = Ok(self.0.clone());
        async move { result }
    }
}

fn make_owner_whois() -> MockWhoIs {
    MockWhoIs(WhoIsResponse {
        node: WhoIsNode {
            name: "owner-kith.tail12345.ts.net".into(),
        },
        user_profile: UserProfile {
            id: OWNER_ID.into(),
            login_name: OWNER_LOGIN.into(),
            display_name: None,
        },
    })
}

// ---------------------------------------------------------------------------
// App factory
// ---------------------------------------------------------------------------

fn make_blob_store() -> std::sync::Arc<kith_attach::BlobStore> {
    let dir = std::env::temp_dir().join(format!(
        "kithd-test-blobs-{}",
        kith_attach::BlobStore::generate_blob_id()
    ));
    let store = std::sync::Arc::new(kith_attach::BlobStore::new(&dir));
    store.init().expect("blob store init must succeed");
    store
}

fn make_app() -> Router {
    let store = Arc::new(Mutex::new(
        Store::open_in_memory().expect("in-memory store must open"),
    ));
    let (events_tx, _events_rx) = make_channel(64);
    let dispatcher = Arc::new(build_dispatcher(Arc::clone(&store)));
    let state = AppState {
        ts: Arc::new(make_owner_whois()),
        store,
        owner_id: OWNER_ID.to_string(),
        owner_login: OWNER_LOGIN.to_string(),
        base_url: kithd::DEFAULT_BASE_URL.to_string(),
        events_tx,
        dispatcher,
        blob_store: make_blob_store(),
    };
    build_app(state).layer(MockConnectInfo(MOCK_ADDR))
}

// ---------------------------------------------------------------------------
// Helper: read response body as a Vec<u8>.
// ---------------------------------------------------------------------------

async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("response body must be readable")
        .to_vec()
}

// ---------------------------------------------------------------------------
// Test 1: GET / → 200 with text/html Content-Type
//
// Oracle: RFC 9110 §15.3.1 — a successful GET must return 200.
// Content-Type for HTML is "text/html" per RFC 2854.
// The body must contain the HTML doctype that is known to be in web/index.html.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn static_get_root_serves_index_html() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    assert_eq!(resp.status(), StatusCode::OK, "GET / must return HTTP 200");

    let ct = resp
        .headers()
        .get("content-type")
        .expect("GET / must return Content-Type header")
        .to_str()
        .expect("Content-Type must be ASCII");

    // Oracle: HTML files are served as text/html (RFC 2854).
    assert!(
        ct.starts_with("text/html"),
        "Content-Type must start with text/html; got: {ct}"
    );

    let body = body_bytes(resp).await;
    let body_str = std::str::from_utf8(&body).expect("index.html must be valid UTF-8");

    // Oracle: web/index.html begins with "<!DOCTYPE html>" — this is a known
    // value from the file on disk, not derived from any code path.
    assert!(
        body_str.contains("<!DOCTYPE html>"),
        "body must contain HTML doctype; got: {body_str:.200}"
    );
}

// ---------------------------------------------------------------------------
// Test 2: GET /index.html → 200 with text/html Content-Type
//
// Oracle: same as Test 1; the explicit path /index.html must return the
// same file as /.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn static_get_index_html_serves_html() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/index.html")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /index.html must return HTTP 200"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .expect("GET /index.html must return Content-Type header")
        .to_str()
        .expect("Content-Type must be ASCII");

    assert!(
        ct.starts_with("text/html"),
        "Content-Type must start with text/html; got: {ct}"
    );

    let body = body_bytes(resp).await;
    let body_str = std::str::from_utf8(&body).expect("index.html must be valid UTF-8");

    // Oracle: same as GET / — the doctype is present in the known file.
    assert!(
        body_str.contains("<!DOCTYPE html>"),
        "body must contain HTML doctype; got: {body_str:.200}"
    );
}

// ---------------------------------------------------------------------------
// Test 3: GET /style.css → 200 with text/css Content-Type
//
// Oracle: RFC 2318 defines text/css as the MIME type for CSS stylesheets.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn static_get_style_css_serves_css() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/style.css")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /style.css must return HTTP 200"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .expect("GET /style.css must return Content-Type header")
        .to_str()
        .expect("Content-Type must be ASCII");

    // Oracle: RFC 2318 — CSS MIME type is text/css.
    assert!(
        ct.starts_with("text/css"),
        "Content-Type must start with text/css; got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: GET /app.js → 200 with JavaScript Content-Type
//
// Oracle: IANA registry lists "application/javascript" as the canonical type
// for JavaScript (RFC 9239); "text/javascript" is an acceptable legacy alias.
// Both are valid.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn static_get_app_js_serves_javascript() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/app.js")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /app.js must return HTTP 200"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .expect("GET /app.js must return Content-Type header")
        .to_str()
        .expect("Content-Type must be ASCII");

    // Oracle: IANA registry (RFC 9239) — JS is application/javascript.
    // mime_guess may return either application/javascript or text/javascript;
    // both are acceptable per RFC 9239 §3.
    assert!(
        ct.contains("javascript"),
        "Content-Type must contain 'javascript'; got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: GET /nonexistent (no extension) → 200 SPA fallback (index.html)
//
// Oracle: SPA convention — a path with no file extension is treated as a
// client-side route; the server must return index.html with HTTP 200 so the
// JS router can handle it.  The body must contain the known HTML doctype.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn static_get_no_extension_path_serves_spa_fallback() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/nonexistent-route")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    // Oracle: SPA fallback must return 200, not 404 (client router handles the path).
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /nonexistent-route (no extension) must return HTTP 200 for SPA fallback"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .expect("SPA fallback must return Content-Type header")
        .to_str()
        .expect("Content-Type must be ASCII");

    assert!(
        ct.starts_with("text/html"),
        "SPA fallback Content-Type must start with text/html; got: {ct}"
    );

    let body = body_bytes(resp).await;
    let body_str = std::str::from_utf8(&body).expect("fallback body must be valid UTF-8");

    // Oracle: SPA fallback serves index.html — must contain the known doctype.
    assert!(
        body_str.contains("<!DOCTYPE html>"),
        "SPA fallback body must contain HTML doctype; got: {body_str:.200}"
    );
}

// ---------------------------------------------------------------------------
// Test 6: GET /no-such-file.txt → 404 Not Found
//
// Oracle: RFC 9110 §15.5.5 — a GET for a resource that does not exist MUST
// return 404.  A path with an extension that does not match any embedded
// asset is not a valid SPA route (the extension signals a concrete resource
// request, not a client-side path).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn static_get_unknown_extension_returns_404() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/no-such-file.txt")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    // Oracle: RFC 9110 §15.5.5 — missing resource with explicit extension → 404.
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET /no-such-file.txt must return HTTP 404"
    );
}

// ---------------------------------------------------------------------------
// Test 7: GET /.well-known/jmap → 200 (JMAP session, not shadowed by static)
//
// Oracle: The JMAP route is registered before the static fallback.  axum
// resolves named routes before the fallback handler; therefore the static
// handler must never intercept /.well-known/jmap.  RFC 8620 §2 requires the
// session endpoint to return 200 with a JSON body.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn jmap_session_not_shadowed_by_static_handler() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/jmap")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    // Oracle: RFC 8620 §2 — session endpoint always returns 200 for
    // authenticated callers.  MockWhoIs returns the owner identity so
    // the Caller extractor classifies this request as Owner.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /.well-known/jmap must return 200, not be captured by the static fallback"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .expect("session endpoint must return Content-Type")
        .to_str()
        .expect("Content-Type must be ASCII");

    // Oracle: JMAP session object is JSON, not HTML (static handler would
    // serve HTML; if this is JSON the route was handled by session_handler).
    assert!(
        ct.contains("json"),
        "/.well-known/jmap Content-Type must contain 'json', not HTML; got: {ct}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: GET /chat/v2.1/messages → 200 SPA fallback
//
// Oracle: SPA convention — the dot in "v2.1" is in a non-final path segment.
// The final segment "messages" has no extension, so the path is a client-side
// route and must receive the SPA fallback (index.html, 200).
// Regression guard for the bug where `path.contains('.')` returned true for
// any dot anywhere in the URL, causing false 404s on versioned route prefixes.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn static_get_dot_in_non_final_segment_serves_spa_fallback() {
    let app = make_app();

    let req = Request::builder()
        .method("GET")
        .uri("/chat/v2.1/messages")
        .body(Body::empty())
        .expect("request must construct");

    let resp = app.oneshot(req).await.expect("oneshot must not fail");

    // Oracle: SPA fallback — final segment "messages" has no extension → 200.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /chat/v2.1/messages must return HTTP 200 for SPA fallback (dot is in non-final segment)"
    );

    let ct = resp
        .headers()
        .get("content-type")
        .expect("SPA fallback must return Content-Type header")
        .to_str()
        .expect("Content-Type must be ASCII");

    assert!(
        ct.starts_with("text/html"),
        "SPA fallback Content-Type must start with text/html; got: {ct}"
    );

    let body = body_bytes(resp).await;
    let body_str = std::str::from_utf8(&body).expect("fallback body must be valid UTF-8");

    // Oracle: SPA fallback serves index.html — must contain the known doctype.
    assert!(
        body_str.contains("<!DOCTYPE html>"),
        "SPA fallback body must contain HTML doctype; got: {body_str:.200}"
    );
}
