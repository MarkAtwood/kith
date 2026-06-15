use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use kith_core::{FederationTransport, Role};
use crate::extractors::{AppState, Caller};

/// Maximum upload size: 100 MiB.  Requests larger than this are rejected with
/// 413 before any bytes are written to disk.
const MAX_BLOB_BYTES: usize = 104_857_600;

/// Maximum Content-Type header length to store.  Truncated if exceeded.
const MAX_CONTENT_TYPE_LEN: usize = 256;

/// `POST /jmap/upload/{account_id}` — receive a blob and return its blobId.
///
/// RFC 8620 §6.1 defines the upload endpoint.  Only the owner may upload.
/// The request body is streamed directly to disk via `BlobStore::write_blob_streaming`,
/// which computes SHA-256 incrementally and enforces the size limit without
/// buffering the full body in heap.
///
/// No DB row is written at upload time.  The DB row is created when the
/// returned `blobId` is referenced in a subsequent `Message/set` create.
pub async fn blob_upload_handler<T: FederationTransport>(
    State(state): State<AppState<T>>,
    caller: Caller,
    Path(account_id): Path<String>,
    request: axum::extract::Request,
) -> impl IntoResponse {
    // 1. Owner-only.
    if caller.role != Role::Owner {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    // 2. Account must be the owner or the stable "a-self" alias.
    if account_id != "a-self" && account_id != state.owner_id {
        return (StatusCode::BAD_REQUEST, "invalid account").into_response();
    }

    // 3. Extract Content-Type header; validate format; cap length; default if absent.
    //
    // We must not truncate at a raw byte offset because Content-Type values
    // may contain non-ASCII characters (e.g. in parameter quoted-strings).
    // Slicing a &str at an arbitrary byte index panics if that index falls
    // inside a multi-byte UTF-8 sequence.  We find the char boundary at
    // MAX_CONTENT_TYPE_LEN instead.
    //
    // A supplied Content-Type must have the form "type/subtype" with both parts
    // non-empty.  HeaderValue::to_str() already enforces visible ASCII, so only
    // the structural check is needed here.  A missing header falls back to the
    // safe default "application/octet-stream".
    let content_type = {
        let raw = request
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        if let Some(s) = raw {
            let truncated = if s.len() > MAX_CONTENT_TYPE_LEN {
                let cut = s
                    .char_indices()
                    .nth(MAX_CONTENT_TYPE_LEN)
                    .map_or(s.len(), |(i, _)| i);
                s[..cut].to_string()
            } else {
                s.to_string()
            };
            // Require "type/subtype" format: slash present, neither part empty.
            let slash = truncated.find('/');
            if slash.is_none_or(|i| i == 0 || i + 1 >= truncated.len()) {
                return (StatusCode::BAD_REQUEST, "Content-Type must be type/subtype")
                    .into_response();
            }
            truncated
        } else {
            "application/octet-stream".to_string()
        }
    };

    // 4. Generate blob ID and stream body directly to disk.
    //    write_blob_streaming computes SHA-256 incrementally and enforces the
    //    size limit without buffering the full body.  InvalidInput means body
    //    exceeded MAX_BLOB_BYTES; other errors are storage failures.
    let blob_id = kith_attach::BlobStore::generate_blob_id();
    let (size, sha256) = match state
        .blob_store
        .write_blob_streaming(&blob_id, request.into_body(), MAX_BLOB_BYTES as u64)
        .await
    {
        Ok(result) => result,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "attachment too large").into_response();
        }
        Err(e) => {
            tracing::error!("blob write failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
        }
    };

    // 7. Return 201 Created with blob metadata (RFC 8620 §6.1).
    (
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "accountId": state.owner_id,
            "blobId": blob_id,
            "size": size,
            "type": content_type,
            "sha256": sha256,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use kith_attach::BlobStore;
    use kith_core::{AuthError, ConnectionContext, FederationTransport, Identity, IdentityProvider};
    use kith_events::make_channel;
    use kith_store::Store;
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    use crate::blob::MAX_CONTENT_TYPE_LEN;
    use crate::build_app;
    use crate::build_dispatcher;
    use crate::extractors::AppState;

    struct MockTransport(Identity);

    impl IdentityProvider for MockTransport {
        fn identify_caller(
            &self,
            _ctx: &ConnectionContext,
        ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_ {
            let result = Ok(self.0.clone());
            async move { result }
        }
    }

    impl FederationTransport for MockTransport {
        fn discover_peers(
            &self,
            _port: u16,
        ) -> impl std::future::Future<Output = Result<Vec<kith_core::DiscoveredPeer>, AuthError>> + Send
        {
            async { Ok(vec![]) }
        }

        fn local_owner_id(
            &self,
        ) -> impl std::future::Future<Output = Result<String, AuthError>> + Send {
            async { Ok("test-owner".into()) }
        }

        fn local_addresses(
            &self,
        ) -> impl std::future::Future<Output = Result<Vec<String>, AuthError>> + Send {
            async { Ok(vec![]) }
        }

        fn is_valid_host(&self, _host: &str) -> bool {
            true
        }
    }

    fn make_identity(id: &str, login: &str) -> Identity {
        Identity::new(id.into(), login.into(), None, format!("{id}-kith.tail.ts.net"))
    }

    fn make_blob_store() -> (Arc<BlobStore>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("temp dir for blob store must be created");
        let store = Arc::new(BlobStore::new(dir.path()));
        store.init().expect("blob store init must succeed");
        (store, dir)
    }

    fn make_app(owner_id: &str, transport: MockTransport) -> (Router, tempfile::TempDir) {
        let store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("in-memory store must open"),
        ));
        let (events_tx, _events_rx) = make_channel(std::num::NonZeroUsize::new(64).unwrap());
        let (blob_store, blob_dir) = make_blob_store();
        let dispatcher = Arc::new(build_dispatcher(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            owner_id.to_string(),
        ));
        let state = AppState {
            transport: Arc::new(transport),
            store,
            owner_id: owner_id.to_string(),
            owner_login: format!("{owner_id}@example.com"),
            base_url: crate::DEFAULT_BASE_URL.to_string(),
            events_tx,
            dispatcher,
            blob_store,
        };
        let app = build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
        (app, blob_dir)
    }

    fn make_app_with_peer_contact(
        owner_id: &str,
        owner_transport: MockTransport,
        peer_id: &str,
        peer_login: &str,
    ) -> (Router, tempfile::TempDir) {
        let store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("in-memory store must open"),
        ));
        store
            .lock()
            .expect("store lock must not be poisoned")
            .contacts()
            .upsert(
                peer_id,
                peer_login,
                "peer-kith.tail.ts.net",
                None,
                1_000_000,
            )
            .expect("upsert must succeed");
        let (events_tx, _events_rx) = make_channel(std::num::NonZeroUsize::new(64).unwrap());
        let (blob_store, blob_dir) = make_blob_store();
        let dispatcher = Arc::new(build_dispatcher(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            owner_id.to_string(),
        ));
        let state = AppState {
            transport: Arc::new(owner_transport),
            store,
            owner_id: owner_id.to_string(),
            owner_login: format!("{owner_id}@example.com"),
            base_url: crate::DEFAULT_BASE_URL.to_string(),
            events_tx,
            dispatcher,
            blob_store,
        };
        let app = build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
        (app, blob_dir)
    }

    // -----------------------------------------------------------------------
    // Test: successful upload by owner
    //
    // Oracle: SHA-256 of the 32-byte test payload is computed independently
    // using sha2 directly.  The handler result is compared against this
    // independent computation; the handler code path is not used as its own
    // oracle.  accountId must match the owner_id passed to make_app.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn blob_upload_owner_success() {
        const OWNER_ID: &str = "uid-owner-blob";
        const OWNER_LOGIN: &str = "owner@blob.example.com";

        let payload: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        // Independent oracle: sha2 computed independently of the handler.
        let expected_sha256 = {
            let mut h = Sha256::new();
            h.update(&payload);
            format!("{:x}", h.finalize())
        };

        let (app, _blob_dir) = make_app(OWNER_ID, MockTransport(make_identity(OWNER_ID, OWNER_LOGIN)));

        let req = Request::builder()
            .method("POST")
            .uri(&format!("/jmap/upload/{OWNER_ID}"))
            .header("content-type", "application/octet-stream")
            .body(Body::from(payload.to_vec()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        let blob_id = json["blobId"].as_str().expect("blobId must be a string");
        assert!(!blob_id.is_empty());
        assert_eq!(json["size"].as_u64(), Some(32));
        assert_eq!(json["sha256"].as_str(), Some(expected_sha256.as_str()));
        assert_eq!(
            json["accountId"].as_str(),
            Some(OWNER_ID),
            "accountId must be present in upload response and equal the owner_id"
        );
    }

    #[tokio::test]
    async fn blob_upload_a_self_account_id() {
        const OWNER_ID: &str = "uid-owner-aself";
        const OWNER_LOGIN: &str = "owner@aself.example.com";

        let (app, _blob_dir) = make_app(OWNER_ID, MockTransport(make_identity(OWNER_ID, OWNER_LOGIN)));
        let req = Request::builder()
            .method("POST")
            .uri("/jmap/upload/a-self")
            .header("content-type", "text/plain")
            .body(Body::from(b"hello".to_vec()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn blob_upload_wrong_account_id_returns_400() {
        const OWNER_ID: &str = "uid-owner-acct";
        const OWNER_LOGIN: &str = "owner@acct.example.com";

        let (app, _blob_dir) = make_app(OWNER_ID, MockTransport(make_identity(OWNER_ID, OWNER_LOGIN)));
        let req = Request::builder()
            .method("POST")
            .uri("/jmap/upload/uid-somebody-else")
            .header("content-type", "application/octet-stream")
            .body(Body::from(b"data".to_vec()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // Test: Content-Type truncation for over-length values
    //
    // Oracle: A Content-Type value whose char count exceeds MAX_CONTENT_TYPE_LEN
    // must be truncated to exactly MAX_CONTENT_TYPE_LEN characters.
    //
    // HTTP HeaderValue::to_str() only returns visible ASCII (bytes 32–126 plus
    // tab), so the char-boundary slice in the implementation operates on
    // purely ASCII strings in practice.  The char_indices-based truncation is
    // defensive code that remains correct if the code path is ever widened.
    // This test validates the truncation length and that the handler does not
    // panic or reject the request.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn blob_upload_content_type_truncated_at_char_boundary() {
        const OWNER_ID: &str = "uid-owner-cttrunc";
        const OWNER_LOGIN: &str = "owner@cttrunc.example.com";

        // Build a Content-Type value of MAX_CONTENT_TYPE_LEN + 10 ASCII chars
        // in valid MIME "type/subtype" format: "application/xxxxx...!!!!!!!!!!".
        // The slash must fall within the truncated portion so the truncated
        // value is still a valid MIME type.
        let type_part = "application";
        let subtype_len = MAX_CONTENT_TYPE_LEN - type_part.len() - 1; // -1 for '/'
        let ct_value = format!("{}/{}{}", type_part, "x".repeat(subtype_len), "!!!!!!!!!!");
        assert!(
            ct_value.len() > MAX_CONTENT_TYPE_LEN,
            "test setup: value must exceed MAX_CONTENT_TYPE_LEN bytes"
        );
        assert!(
            ct_value.is_ascii(),
            "test setup: value must be ASCII (matches HTTP visible-ASCII constraint)"
        );
        // The expected truncated value: "application/" + "x".repeat(subtype_len)
        let expected_truncated = format!("{}/{}", type_part, "x".repeat(subtype_len));
        assert_eq!(expected_truncated.len(), MAX_CONTENT_TYPE_LEN);

        let (app, _blob_dir) = make_app(OWNER_ID, MockTransport(make_identity(OWNER_ID, OWNER_LOGIN)));
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/jmap/upload/{OWNER_ID}"))
            .header("content-type", ct_value.as_str())
            .body(Body::from(b"x".to_vec()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // The stored type must be truncated to exactly MAX_CONTENT_TYPE_LEN chars.
        let stored_type = json["type"].as_str().expect("type must be a string");
        assert_eq!(
            stored_type.len(),
            MAX_CONTENT_TYPE_LEN,
            "truncated Content-Type must be exactly MAX_CONTENT_TYPE_LEN chars long"
        );
        assert_eq!(
            stored_type,
            expected_truncated.as_str(),
            "truncated Content-Type must equal the first MAX_CONTENT_TYPE_LEN chars"
        );
    }

    #[tokio::test]
    async fn blob_upload_peer_caller_returns_403() {
        const OWNER_ID: &str = "uid-owner-peer";
        const PEER_ID: &str = "uid-peer-upload";
        const PEER_LOGIN: &str = "peer@upload.example.com";

        let (app, _blob_dir) = make_app_with_peer_contact(
            OWNER_ID,
            MockTransport(make_identity(PEER_ID, PEER_LOGIN)),
            PEER_ID,
            PEER_LOGIN,
        );
        let req = Request::builder()
            .method("POST")
            .uri("/jmap/upload/a-self")
            .header("content-type", "application/octet-stream")
            .body(Body::from(b"data".to_vec()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
