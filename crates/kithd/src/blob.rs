use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sha2::{Digest, Sha256};

use crate::auth::WhoIsProvider;
use crate::extractors::{AppState, Caller};
use kith_core::Role;

/// Maximum upload size: 100 MiB.  Requests larger than this are rejected with
/// 413 before any bytes are written to disk.
const MAX_BLOB_BYTES: usize = 104_857_600;

/// Maximum Content-Type header length to store.  Truncated if exceeded.
const MAX_CONTENT_TYPE_LEN: usize = 256;

/// `POST /jmap/upload/{account_id}` — receive a blob and return its blobId.
///
/// RFC 8620 §6.1 defines the upload endpoint.  Only the owner may upload.
/// The request body is buffered (up to `MAX_BLOB_BYTES`), then written to
/// disk via `BlobStore::write_blob`.  SHA-256 is computed over the buffered
/// bytes independently before writing, so the hash in the response is always
/// consistent with the bytes on disk.
///
/// No DB row is written at upload time.  The DB row is created when the
/// returned `blobId` is referenced in a subsequent `Message/set` create.
pub async fn blob_upload_handler<W: WhoIsProvider + Send + Sync + 'static>(
    State(state): State<AppState<W>>,
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

    // 3. Extract Content-Type header; cap length; default if absent.
    let content_type = request
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            if s.len() > MAX_CONTENT_TYPE_LEN {
                &s[..MAX_CONTENT_TYPE_LEN]
            } else {
                s
            }
        })
        .unwrap_or("application/octet-stream")
        .to_string();

    // 4. Buffer body with a hard size cap.  Read one byte over the limit so
    //    we can distinguish "exactly at limit" from "exceeded".
    let bytes = match axum::body::to_bytes(request.into_body(), MAX_BLOB_BYTES + 1).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "attachment too large").into_response();
        }
    };
    if bytes.len() > MAX_BLOB_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "attachment too large").into_response();
    }

    // 5. Compute SHA-256 over the buffered bytes.  This is an independent
    //    oracle — the hash is derived from the bytes that will be written to
    //    disk, so the client can verify the transfer without re-downloading.
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        format!("{:x}", hasher.finalize())
    };
    let size = bytes.len() as u64;

    // 6. Generate blob ID and write to disk.
    let blob_id = kith_attach::BlobStore::generate_blob_id();
    if let Err(e) = state.blob_store.write_blob(&blob_id, &bytes).await {
        tracing::error!("blob write failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
    }

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
    use kith_core::AuthError;
    use kith_events::make_channel;
    use kith_store::Store;
    use kith_tslocal::{UserProfile, WhoIsNode, WhoIsResponse};
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    use crate::auth::WhoIsProvider;
    use crate::build_app;
    use crate::build_dispatcher;
    use crate::extractors::AppState;

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

    fn make_whois(id: &str, login: &str) -> WhoIsResponse {
        WhoIsResponse {
            node: WhoIsNode {
                name: format!("{id}-kith.tail.ts.net"),
            },
            user_profile: UserProfile {
                id: id.into(),
                login_name: login.into(),
                display_name: None,
            },
        }
    }

    fn make_blob_store() -> Arc<BlobStore> {
        let dir =
            std::env::temp_dir().join(format!("kithd-blob-test-{}", BlobStore::generate_blob_id()));
        let store = Arc::new(BlobStore::new(&dir));
        store.init().expect("blob store init must succeed");
        store
    }

    fn make_app(owner_id: &str, whois: MockWhoIs) -> Router {
        let store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("in-memory store must open"),
        ));
        let (events_tx, _events_rx) = make_channel(64);
        let dispatcher = Arc::new(build_dispatcher(Arc::clone(&store), owner_id));
        let state = AppState {
            ts: Arc::new(whois),
            store,
            owner_id: owner_id.to_string(),
            owner_login: format!("{owner_id}@example.com"),
            base_url: crate::DEFAULT_BASE_URL.to_string(),
            events_tx,
            dispatcher,
            blob_store: make_blob_store(),
        };
        build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))))
    }

    fn make_app_with_peer_contact(
        owner_id: &str,
        owner_whois: MockWhoIs,
        peer_id: &str,
        peer_login: &str,
    ) -> Router {
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
        let (events_tx, _events_rx) = make_channel(64);
        let dispatcher = Arc::new(build_dispatcher(Arc::clone(&store), owner_id));
        let state = AppState {
            ts: Arc::new(owner_whois),
            store,
            owner_id: owner_id.to_string(),
            owner_login: format!("{owner_id}@example.com"),
            base_url: crate::DEFAULT_BASE_URL.to_string(),
            events_tx,
            dispatcher,
            blob_store: make_blob_store(),
        };
        build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))))
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

        let app = make_app(OWNER_ID, MockWhoIs(make_whois(OWNER_ID, OWNER_LOGIN)));

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

        let app = make_app(OWNER_ID, MockWhoIs(make_whois(OWNER_ID, OWNER_LOGIN)));
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

        let app = make_app(OWNER_ID, MockWhoIs(make_whois(OWNER_ID, OWNER_LOGIN)));
        let req = Request::builder()
            .method("POST")
            .uri("/jmap/upload/uid-somebody-else")
            .header("content-type", "application/octet-stream")
            .body(Body::from(b"data".to_vec()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn blob_upload_peer_caller_returns_403() {
        const OWNER_ID: &str = "uid-owner-peer";
        const PEER_ID: &str = "uid-peer-upload";
        const PEER_LOGIN: &str = "peer@upload.example.com";

        let app = make_app_with_peer_contact(
            OWNER_ID,
            MockWhoIs(make_whois(PEER_ID, PEER_LOGIN)),
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
