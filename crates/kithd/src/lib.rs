pub mod auth;
pub mod blob;
pub mod config;
pub mod discovery;
pub mod events;
pub mod extractors;
pub mod listener;
pub mod logging;
pub(crate) mod peer_fetch;

/// Call this at the start of integration tests that need `fetch_peer_blob` to
/// connect to 127.0.0.1 test servers.  Must be called before any fetch.
/// Has no effect on production binaries (cfg-gated).
#[cfg(any(test, feature = "test-utils"))]
pub fn allow_loopback_for_tests() {
    peer_fetch::ALLOW_LOOPBACK_FOR_TESTS.store(true, std::sync::atomic::Ordering::Relaxed);
}
pub mod signal;
pub mod static_files;
pub mod tls;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use axum::{extract::State, Json};
use extractors::{AppState, Caller};
use kith_attach::BlobStore;
use kith_chat::chat::{ChatChangesHandler, ChatGetHandler, ChatQueryHandler, ChatSetHandler};
use kith_chat::contact::{
    ChatContactChangesHandler, ChatContactGetHandler, ChatContactQueryChangesHandler,
    ChatContactQueryHandler, ChatContactSetHandler,
};
use kith_chat::message::{
    MessageChangesHandler, MessageGetHandler, MessageQueryChangesHandler, MessageQueryHandler,
    MessageSetHandler,
};
use kith_chat::space::{
    SpaceBanChangesHandler, SpaceBanGetHandler, SpaceBanSetHandler, SpaceChangesHandler,
    SpaceGetHandler, SpaceInviteChangesHandler, SpaceInviteGetHandler, SpaceInviteSetHandler,
    SpaceJoinHandler, SpaceQueryHandler, SpaceSetHandler,
};
use kith_core::Role;
use kith_jmap::{build_session, parse_request, request_error, Dispatcher};
use kith_peer::{DeliverHandler, ReceiptHandler};
use kith_store::Store;
use std::sync::{Arc, Mutex};
use tokio_util::io::ReaderStream;
use tower_http::trace::TraceLayer;

use auth::WhoIsProvider;

/// Base URL used in Session object URL fields.
///
/// In production this should be derived from the tailnet IP returned by
/// LocalAPI /status.  For v1 it is read from KITHD_BASE_URL (default:
/// "https://kith.local").
pub const DEFAULT_BASE_URL: &str = "https://kith.local";

/// Read and validate the base URL from environment variables.
///
/// Reads `KITHD_BASE_URL` first; falls back to the deprecated `KITH_BASE_URL`
/// (with a one-time warning), then to `DEFAULT_BASE_URL`.  Must be called
/// once at startup and stored in `AppState` — do not call per request.
///
/// Returns `Err` with an actionable message if the variable is set but does
/// not start with `https://`.  The caller should treat this as a fatal startup
/// error — the JMAP Session `downloadUrl` template will be wrong with any
/// non-HTTPS base, and serving unencrypted URLs would break clients.
pub fn resolve_base_url() -> Result<String, String> {
    let raw = if let Ok(v) = std::env::var("KITHD_BASE_URL") {
        v
    } else if let Ok(v) = std::env::var("KITH_BASE_URL") {
        tracing::warn!("KITH_BASE_URL is deprecated; use KITHD_BASE_URL instead");
        v
    } else {
        return Ok(DEFAULT_BASE_URL.to_string());
    };
    if raw.starts_with("https://") {
        Ok(raw)
    } else {
        Err(format!(
            "KITHD_BASE_URL {:?} does not start with https:// — \
             kithd only serves JMAP over HTTPS; fix the URL or unset KITHD_BASE_URL \
             to use the default ({})",
            raw, DEFAULT_BASE_URL
        ))
    }
}

/// Derive a single opaque session-state string from all three JMAP counters.
///
/// The string changes whenever any object-type counter advances, so a client
/// can detect session-level changes by comparing this value.  The format is
/// an implementation detail and must be treated as opaque by callers.
pub fn combined_state(store: &Store) -> String {
    match store.get_all_states() {
        Ok(states) => {
            let parts: Vec<&str> = states.iter().map(|(_, s)| s.as_str()).collect();
            parts.join("-")
        }
        Err(e) => {
            tracing::error!("get_all_states failed — state will appear as s-0: {e}");
            "s-0-s-0-s-0".to_string()
        }
    }
}

/// `GET /.well-known/jmap` — returns a JMAP Session object for the caller.
pub async fn session_handler<W: WhoIsProvider + Send + Sync + 'static>(
    State(app): State<AppState<W>>,
    caller: Caller,
) -> impl axum::response::IntoResponse {
    let state_str = match app.store.lock() {
        Ok(guard) => combined_state(&guard),
        Err(e) => {
            tracing::error!("store mutex poisoned in session_handler: {e}");
            "s-0-s-0-s-0".to_string()
        }
    };

    let session = build_session(
        caller.role,
        &caller.identity,
        &app.base_url,
        state_str,
        app.owner_id.clone(),
        app.owner_login.clone(),
    );
    Json(session)
}

/// `POST /jmap/api` — parse and dispatch a JMAP request.
///
/// The verified caller identity is passed to the dispatcher as a typed
/// parameter and forwarded directly to peer-role handlers (`Peer/deliver`,
/// `Peer/receipt`) without JSON injection.
pub async fn jmap_handler<W: WhoIsProvider + Send + Sync + 'static>(
    State(app): State<AppState<W>>,
    caller: Caller,
    Json(body): Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    // Step 1: parse and validate the request envelope.
    let request = match parse_request(body) {
        Ok(r) => r,
        Err(e) => return request_error(e).into_response(),
    };

    // Step 2: read current session state from the store (before dispatch).
    let session_state = match app.store.lock() {
        Ok(guard) => combined_state(&guard),
        Err(e) => {
            tracing::error!("store mutex poisoned in jmap_handler: {e}");
            "s-0-s-0-s-0".to_string()
        }
    };

    // Step 3: dispatch.  Caller identity is passed as a typed parameter; the
    // dispatcher routes it directly to peer handlers (Peer/deliver, Peer/receipt)
    // without JSON injection.
    let response = app
        .dispatcher
        .dispatch(request, caller.role, caller.identity, session_state)
        .await;

    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&response).expect("JmapResponse always serializes"),
        ))
        .unwrap()
}

/// `GET /jmap/download/:account_id/:blob_id/:name` — serve a stored blob.
///
/// Owner-only.  The `account_id` path segment must match `state.owner_id` or
/// the stable alias `"a-self"` (which the session's `downloadUrl` template
/// emits as the account key).  The `blob_id` is validated by
/// [`BlobStore::validate_blob_id`]; an invalid ID returns 400 before any
/// disk I/O.
///
/// Content-Type is read from the `attachments` table (stored at message
/// creation time under server control).  Falls back to
/// `application/octet-stream` if the blob has no metadata row.  The
/// `?accept=` query parameter is intentionally ignored — reflecting it would
/// allow a malicious peer to store an HTML blob and trigger stored-XSS by
/// serving it with `Content-Type: text/html`.
///
/// Content-Disposition is set to `attachment; filename="<sanitized_name>"`.
/// The filename is the last path segment from the URL, stripped of path
/// separators and null bytes and clamped to 255 characters.
pub async fn blob_download_handler<W: WhoIsProvider + Send + Sync + 'static>(
    State(state): State<AppState<W>>,
    caller: Caller,
    Path((account_id, blob_id, name)): Path<(String, String, String)>,
) -> impl IntoResponse {
    // 1. Owner-only.
    if caller.role != Role::Owner {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }

    // 2. Account must match the daemon owner.  "a-self" is the stable JMAP
    //    alias used in the session's downloadUrl template; accept either form.
    if account_id != state.owner_id && account_id != "a-self" {
        return (StatusCode::BAD_REQUEST, "wrong accountId").into_response();
    }

    // 3. Validate blob ID before any disk access.
    if BlobStore::validate_blob_id(&blob_id).is_err() {
        return (StatusCode::BAD_REQUEST, "invalid blobId").into_response();
    }

    // 4. Open blob file for streaming.  On a local miss, attempt a peer fetch
    //    before giving up.
    let path = state.blob_store.blob_path(&blob_id);
    let (file, file_len, serve_content_type, serve_filename) = match tokio::fs::File::open(&path)
        .await
    {
        Ok(f) => {
            // Stat to get file size for Content-Length before streaming.
            let file_len: Option<u64> = f.metadata().await.ok().map(|m| m.len());
            // Local hit: look up content-type from the DB (stored at message
            // creation time under server control).  Never reflect the ?accept=
            // URL parameter as Content-Type — that path would let a peer deliver
            // an HTML blob and supply ?accept=text/html to execute it in the
            // browser's kithd origin (stored XSS).
            //
            // Falls back to application/octet-stream for blobs uploaded but not
            // yet referenced in any message (the pre-Message/set upload window).
            let ct = match state.store.lock() {
                Err(_) => {
                    tracing::error!("store lock poisoned during blob metadata lookup");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
                }
                Ok(guard) => match guard.attachments().get(&blob_id) {
                    Ok(Some(info)) => info.content_type,
                    Ok(None) => "application/octet-stream".to_string(),
                    Err(e) => {
                        tracing::warn!("attachment metadata lookup failed for id={blob_id:?}: {e}");
                        "application/octet-stream".to_string()
                    }
                },
            };
            let sanitized: String = name
                .chars()
                .filter(|&c| matches!(c, ' '..='~') && !matches!(c, '"' | ';' | '/' | '\\'))
                .take(255)
                .collect();
            (f, file_len, ct, sanitized)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Local miss: look up which peer owns this blob.
            let peer_info = match state.store.lock() {
                Err(_) => {
                    tracing::error!("store lock poisoned during peer blob lookup");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
                }
                Ok(guard) => guard.get_peer_mailbox_for_blob(&blob_id),
            };
            let info = match peer_info {
                Ok(None) => return (StatusCode::NOT_FOUND, "not found").into_response(),
                Err(e) => {
                    tracing::warn!("get_peer_mailbox_for_blob db error for id={blob_id:?}: {e}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
                }
                Ok(Some(info)) => info,
            };
            // Fetch from peer — must not hold any lock across this await.
            match crate::peer_fetch::fetch_peer_blob(
                &state.blob_store,
                &info.mailbox_host,
                &blob_id,
                &info.filename,
                &info.content_type,
                &info.sha256,
                info.size_bytes,
            )
            .await
            {
                Ok(()) => {}
                Err(crate::peer_fetch::FetchBlobError::Timeout)
                | Err(crate::peer_fetch::FetchBlobError::Network(_)) => {
                    return (StatusCode::BAD_GATEWAY, "peer unavailable").into_response();
                }
                Err(crate::peer_fetch::FetchBlobError::HttpError(404)) => {
                    return (StatusCode::NOT_FOUND, "not found on peer").into_response();
                }
                Err(crate::peer_fetch::FetchBlobError::HttpError(_)) => {
                    return (StatusCode::BAD_GATEWAY, "peer unavailable").into_response();
                }
                Err(crate::peer_fetch::FetchBlobError::HashMismatch { .. })
                | Err(crate::peer_fetch::FetchBlobError::SizeExceeded) => {
                    tracing::error!("blob integrity error during peer fetch for id={blob_id:?}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "blob integrity error")
                        .into_response();
                }
                Err(crate::peer_fetch::FetchBlobError::HostRejected)
                | Err(crate::peer_fetch::FetchBlobError::BlobIdInvalid) => {
                    return (StatusCode::FORBIDDEN, "peer host rejected").into_response();
                }
                Err(crate::peer_fetch::FetchBlobError::BlobStore(e)) => {
                    tracing::error!("blob store error during peer fetch for id={blob_id:?}: {e}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response();
                }
            }
            // Re-open the now-cached blob.
            let f = match tokio::fs::File::open(&path).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("blob open after peer fetch failed for id={blob_id:?}: {e}");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "read error").into_response();
                }
            };
            // Stat to get actual file size for Content-Length — do not use the
            // DB-recorded size_bytes, which is peer-supplied and untrustworthy.
            let file_len: Option<u64> = f.metadata().await.ok().map(|m| m.len());
            // Use DB metadata for content-type and filename (not URL params).
            // Sanitize filename from DB the same way as the local-hit path:
            // strip chars that could escape the Content-Disposition quoted string.
            let sanitized_peer: String = info
                .filename
                .chars()
                .filter(|&c| matches!(c, ' '..='~') && !matches!(c, '"' | ';' | '/' | '\\'))
                .take(255)
                .collect();
            (f, file_len, info.content_type, sanitized_peer)
        }
        Err(e) => {
            tracing::error!("blob open failed for id={blob_id:?}: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "read error").into_response();
        }
    };

    // 5. Build streaming response using content-type and filename resolved above.
    let content_disposition = format!("attachment; filename=\"{}\"", serve_filename);
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let mut builder = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, serve_content_type)
        .header(header::CONTENT_DISPOSITION, content_disposition);
    if let Some(len) = file_len {
        builder = builder.header(header::CONTENT_LENGTH, len);
    }
    builder.body(body).unwrap()
}

/// Build the JMAP method dispatcher with all registered handlers.
pub fn build_dispatcher(
    store: Arc<Mutex<Store>>,
    blob_store: Arc<BlobStore>,
    owner_id: String,
) -> Dispatcher {
    let mut d = Dispatcher::new();

    // Contact methods (owner-only)
    d.register(
        "ChatContact/get",
        Box::new(ChatContactGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "ChatContact/set",
        Box::new(ChatContactSetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "ChatContact/changes",
        Box::new(ChatContactChangesHandler::new(Arc::clone(&store))),
    );
    d.register(
        "ChatContact/query",
        Box::new(ChatContactQueryHandler::new(Arc::clone(&store))),
    );
    d.register(
        "ChatContact/queryChanges",
        Box::new(ChatContactQueryChangesHandler::new(Arc::clone(&store))),
    );

    // Chat methods (owner-only)
    d.register(
        "Chat/get",
        Box::new(ChatGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Chat/set",
        Box::new(ChatSetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Chat/changes",
        Box::new(ChatChangesHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Chat/query",
        Box::new(ChatQueryHandler::new(Arc::clone(&store))),
    );

    // Message methods (owner-only)
    d.register(
        "Message/get",
        Box::new(MessageGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Message/set",
        Box::new(MessageSetHandler::new(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            owner_id.clone(),
        )),
    );
    d.register(
        "Message/changes",
        Box::new(MessageChangesHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Message/query",
        Box::new(MessageQueryHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Message/queryChanges",
        Box::new(MessageQueryChangesHandler::new(Arc::clone(&store))),
    );

    // Space methods (owner-only)
    d.register(
        "Space/get",
        Box::new(SpaceGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Space/set",
        Box::new(SpaceSetHandler::new(
            Arc::clone(&store),
            owner_id.clone(),
        )),
    );
    d.register(
        "Space/changes",
        Box::new(SpaceChangesHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Space/query",
        Box::new(SpaceQueryHandler::new(Arc::clone(&store))),
    );
    d.register(
        "Space/join",
        Box::new(SpaceJoinHandler::new(
            Arc::clone(&store),
            owner_id.clone(),
        )),
    );

    // SpaceInvite methods (owner-only)
    d.register(
        "SpaceInvite/get",
        Box::new(SpaceInviteGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "SpaceInvite/set",
        Box::new(SpaceInviteSetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "SpaceInvite/changes",
        Box::new(SpaceInviteChangesHandler::new(Arc::clone(&store))),
    );

    // SpaceBan methods (owner-only)
    d.register(
        "SpaceBan/get",
        Box::new(SpaceBanGetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "SpaceBan/set",
        Box::new(SpaceBanSetHandler::new(Arc::clone(&store))),
    );
    d.register(
        "SpaceBan/changes",
        Box::new(SpaceBanChangesHandler::new(Arc::clone(&store))),
    );

    // Peer methods — use register_peer so the dispatcher passes the verified
    // caller Identity as a typed parameter instead of injecting it into args.
    d.register_peer(
        "Peer/deliver",
        Box::new(DeliverHandler::new(Arc::clone(&store))),
    );
    d.register_peer(
        "Peer/receipt",
        Box::new(ReceiptHandler::new(Arc::clone(&store), owner_id.clone())),
    );

    d
}

/// Build the axum router for kithd.
///
/// Generic over `W` so tests can inject a `MockWhoIs` instead of `LocalApiClient`.
/// In production, `W = LocalApiClient`.
pub fn build_app<W: WhoIsProvider + Send + Sync + 'static>(state: AppState<W>) -> Router {
    Router::new()
        .route("/.well-known/jmap", get(session_handler::<W>))
        .route(
            "/jmap/api",
            // Enforce the 10 MiB max_size_request limit advertised in the session.
            // Applied at the route level so the blob upload endpoint (which has its
            // own 100 MiB cap enforced in the handler) is not affected.
            post(jmap_handler::<W>).layer(DefaultBodyLimit::max(10 * 1024 * 1024)),
        )
        .route("/jmap/events", get(events::events_handler::<W>))
        .route(
            "/jmap/upload/{account_id}",
            post(blob::blob_upload_handler::<W>),
        )
        .route(
            "/jmap/download/{account_id}/{blob_id}/{name}",
            get(blob_download_handler::<W>),
        )
        .fallback(static_files::static_handler)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Spawn a kithd HTTPS listener on an OS-assigned loopback port.
///
/// The TLS certificate is generated once per test process via `OnceLock` and
/// reused across all test invocations.  Callers receive the DER bytes so they
/// can configure a pinned trust root (e.g. `PeerHttpClient::new_with_root_cert`).
///
/// Returns `(local_addr, cert_der_bytes, join_handle)`.  The caller is
/// responsible for calling `handle.abort()` to stop the server.
///
/// Only available in test builds (`#[cfg(any(test, feature = "test-utils"))]`).
#[cfg(any(test, feature = "test-utils"))]
pub async fn spawn_test_listener<W>(
    state: AppState<W>,
) -> Result<(std::net::SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>>
where
    W: crate::auth::WhoIsProvider + Send + Sync + 'static,
{
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use hyper_util::service::TowerToHyperService;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use std::net::SocketAddr;
    use std::sync::{Arc, OnceLock};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tower::Service;

    // Generate cert+key DER bytes once per test process; reuse across all
    // test invocations to avoid per-test rcgen overhead.
    static SHARED_TEST_CERT: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    // get_or_init returns &(Vec<u8>, Vec<u8>); copy to owned before use.
    let (cert_der, key_der) = {
        let pair = SHARED_TEST_CERT.get_or_init(|| {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["kith.local".to_string()])
                    .expect("test cert generation must succeed");
            (cert.der().to_vec(), signing_key.serialize_der())
        });
        (pair.0.clone(), pair.1.clone())
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der)),
        )?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;

    let mut make_svc = build_app(state).into_make_service_with_connect_info::<SocketAddr>();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, peer_addr)) = listener.accept().await else {
                break;
            };
            let acceptor = tls_acceptor.clone();
            let Ok(tls) = acceptor.accept(tcp).await else {
                continue;
            };
            let io = TokioIo::new(tls);
            // IntoMakeServiceWithConnectInfo::call is infallible (Infallible error).
            let svc = make_svc
                .call(peer_addr)
                .await
                .expect("make_service is infallible");
            let hyper_svc = TowerToHyperService::new(svc);
            tokio::spawn(async move {
                auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, hyper_svc)
                    .await
                    .unwrap_or_else(|e| tracing::debug!("connection error: {e}"));
            });
        }
    });

    Ok((local_addr, cert_der, handle))
}

// -----------------------------------------------------------------------
// resolve_base_url tests
// -----------------------------------------------------------------------
// Each test sets and clears env vars within the test.  These tests must not
// be run in parallel with other tests that read KITHD_BASE_URL or
// KITH_BASE_URL — Rust's test runner uses one thread by default, so this
// is safe with the default settings.
#[cfg(test)]
mod resolve_base_url_tests {
    use super::*;

    struct EnvGuard {
        key: &'static str,
        prior: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prior = std::env::var(key).ok();
            unsafe { std::env::set_var(key, val) };
            Self { key, prior }
        }
        fn remove(key: &'static str) -> Self {
            let prior = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self { key, prior }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn resolve_base_url_neither_var_returns_default() {
        // Oracle: DEFAULT_BASE_URL constant — no env var set.
        let _g1 = EnvGuard::remove("KITHD_BASE_URL");
        let _g2 = EnvGuard::remove("KITH_BASE_URL");
        let result = resolve_base_url();
        assert_eq!(result.unwrap(), DEFAULT_BASE_URL);
    }

    #[test]
    fn resolve_base_url_valid_https_accepted() {
        // Oracle: a valid https:// URL is returned unchanged.
        let _g1 = EnvGuard::set("KITHD_BASE_URL", "https://alice-kith.tail.ts.net");
        let _g2 = EnvGuard::remove("KITH_BASE_URL");
        let result = resolve_base_url();
        assert_eq!(result.unwrap(), "https://alice-kith.tail.ts.net");
    }

    #[test]
    fn resolve_base_url_non_https_returns_err() {
        // Oracle: a non-https URL is a fatal config error, not a silent fallback.
        let _g1 = EnvGuard::set("KITHD_BASE_URL", "http://alice-kith.tail.ts.net");
        let _g2 = EnvGuard::remove("KITH_BASE_URL");
        let result = resolve_base_url();
        assert!(
            result.is_err(),
            "non-https KITHD_BASE_URL must return Err, not Ok"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("does not start with https://"),
            "error message must mention https://; got: {msg}"
        );
    }

    #[test]
    fn resolve_base_url_http_scheme_returns_err() {
        // Oracle: http:// (no S) must be rejected — identical check as non-https.
        let _g1 = EnvGuard::set("KITHD_BASE_URL", "http://example.com");
        let _g2 = EnvGuard::remove("KITH_BASE_URL");
        assert!(
            resolve_base_url().is_err(),
            "http:// must be rejected as non-https"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use kith_attach::BlobStore;
    use kith_core::{auth::Role, AuthError, Identity, JmapRequest};
    use kith_events::make_channel;
    use kith_store::Store;
    use kith_tslocal::{UserProfile, WhoIsNode, WhoIsResponse};
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn dummy_identity() -> Identity {
        Identity {
            user_id: "uid-test".to_string(),
            login_name: "test@example.com".to_string(),
            display_name: None,
            node_name: "test-node.tail12345.ts.net".to_string(),
        }
    }

    use crate::auth::WhoIsProvider;
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

    fn make_blob_store_for_test() -> (Arc<BlobStore>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("TempDir::new must succeed");
        let store = Arc::new(BlobStore::new(dir.path()));
        store.init().expect("blob store init must succeed");
        (store, dir)
    }

    fn make_app_for_test(
        owner_id: &str,
        whois: MockWhoIs,
    ) -> (Router, Arc<BlobStore>, tempfile::TempDir) {
        let store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("in-memory store must open"),
        ));
        let (events_tx, _events_rx) = make_channel(64);
        let (blob_store, blob_dir) = make_blob_store_for_test();
        let dispatcher = Arc::new(build_dispatcher(
            Arc::clone(&store),
            Arc::clone(&blob_store),
            owner_id.to_string(),
        ));
        let state = AppState {
            ts: Arc::new(whois),
            store,
            owner_id: owner_id.to_string(),
            owner_login: format!("{owner_id}@example.com"),
            base_url: DEFAULT_BASE_URL.to_string(),
            events_tx,
            dispatcher,
            blob_store: Arc::clone(&blob_store),
        };
        let app = build_app(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
        (app, blob_store, blob_dir)
    }

    // Oracle: every method listed in kith-architecture.md must be dispatched
    // by the production build_dispatcher without returning unknownMethod.
    //
    // This is the non-circular companion to the kith-jmap
    // method_roles_contains_expected_methods test.  That test verifies
    // METHOD_ROLES matches the spec; this test verifies build_dispatcher
    // actually registers a handler for each spec method.
    //
    // Failure mode caught: adding a method to METHOD_ROLES but forgetting
    // to call d.register() in build_dispatcher.
    #[tokio::test]
    async fn build_dispatcher_registers_all_spec_methods() {
        let store = Store::open_in_memory().unwrap();
        let (blob_store, _blob_dir) = make_blob_store_for_test();
        let dispatcher = build_dispatcher(
            Arc::new(Mutex::new(store)),
            blob_store,
            "uid-test-owner".to_string(),
        );

        // (method_name, role_required_by_spec)
        let owner_methods = [
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
            "Space/get",
            "Space/set",
            "Space/changes",
            "SpaceInvite/get",
            "SpaceInvite/set",
            "SpaceInvite/changes",
            "SpaceBan/get",
            "SpaceBan/set",
            "SpaceBan/changes",
        ];
        let peer_methods = ["Peer/deliver", "Peer/receipt"];

        for method in owner_methods {
            let req = JmapRequest::new(
                vec!["urn:ietf:params:jmap:chat".to_string()],
                vec![(method.to_string(), serde_json::json!({}), "r0".to_string())],
                None,
            );
            let resp = dispatcher
                .dispatch(req, Role::Owner, dummy_identity(), "s-0".to_string())
                .await;
            let first = &resp.method_responses[0];
            let error_type = first.1.get("type").and_then(|v| v.as_str());
            assert_ne!(
                error_type,
                Some("unknownMethod"),
                "build_dispatcher missing handler for owner method '{method}'",
            );
        }

        for method in peer_methods {
            let req = JmapRequest::new(
                vec!["urn:ietf:params:jmap:chat".to_string()],
                vec![(method.to_string(), serde_json::json!({}), "r0".to_string())],
                None,
            );
            let resp = dispatcher
                .dispatch(req, Role::Peer, dummy_identity(), "s-0".to_string())
                .await;
            let first = &resp.method_responses[0];
            let error_type = first.1.get("type").and_then(|v| v.as_str());
            assert_ne!(
                error_type,
                Some("unknownMethod"),
                "build_dispatcher missing handler for peer method '{method}'",
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test: download with "a-self" account_id returns 200.
    //
    // Oracle: a blob is written directly to the BlobStore (independent of the
    // upload handler).  The download is issued with account_id = "a-self" and
    // must return 200 with the original bytes.  This exercises the fix for the
    // bug where the download handler rejected the "a-self" alias.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn blob_download_a_self_account_id_returns_200() {
        const OWNER_ID: &str = "uid-owner-dl-aself";
        const OWNER_LOGIN: &str = "owner@dl-aself.example.com";

        let (app, blob_store, _blob_dir) =
            make_app_for_test(OWNER_ID, MockWhoIs(make_whois(OWNER_ID, OWNER_LOGIN)));

        // Write a known blob directly — independent of the upload handler path.
        let blob_id = BlobStore::generate_blob_id();
        let payload = b"download-test-payload";
        blob_store
            .write_blob(&blob_id, payload)
            .await
            .expect("write_blob must succeed");

        // Download using "a-self" as the account_id.
        let req = Request::builder()
            .method("GET")
            .uri(format!("/jmap/download/a-self/{blob_id}/file.bin"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "download with a-self account_id must return 200"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            body_bytes.as_ref(),
            payload,
            "downloaded bytes must equal the written payload"
        );
    }

    // -----------------------------------------------------------------------
    // Test: download with wrong account_id returns 400.
    //
    // Oracle: any account_id that is neither owner_id nor "a-self" must be
    // rejected before any disk I/O.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn blob_download_wrong_account_id_returns_400() {
        const OWNER_ID: &str = "uid-owner-dl-badacct";
        const OWNER_LOGIN: &str = "owner@dl-badacct.example.com";

        let (app, blob_store, _blob_dir) =
            make_app_for_test(OWNER_ID, MockWhoIs(make_whois(OWNER_ID, OWNER_LOGIN)));

        let blob_id = BlobStore::generate_blob_id();
        blob_store
            .write_blob(&blob_id, b"irrelevant")
            .await
            .expect("write_blob must succeed");

        let req = Request::builder()
            .method("GET")
            .uri(format!(
                "/jmap/download/uid-somebody-else/{blob_id}/file.bin"
            ))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "download with wrong account_id must return 400"
        );
    }

    // -----------------------------------------------------------------------
    // Test: download with literal owner_id as account_id returns 200.
    //
    // Oracle: same as the a-self test — blob written directly; download
    // exercised with the literal owner_id string.  Confirms the pre-existing
    // code path still works after the fix.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn blob_download_owner_id_account_id_returns_200() {
        const OWNER_ID: &str = "uid-owner-dl-literal";
        const OWNER_LOGIN: &str = "owner@dl-literal.example.com";

        let (app, blob_store, _blob_dir) =
            make_app_for_test(OWNER_ID, MockWhoIs(make_whois(OWNER_ID, OWNER_LOGIN)));

        let blob_id = BlobStore::generate_blob_id();
        let payload = b"literal-owner-id-download";
        blob_store
            .write_blob(&blob_id, payload)
            .await
            .expect("write_blob must succeed");

        let req = Request::builder()
            .method("GET")
            .uri(format!("/jmap/download/{OWNER_ID}/{blob_id}/file.bin"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "download with literal owner_id as account_id must return 200"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(
            body_bytes.as_ref(),
            payload,
            "downloaded bytes must equal the written payload"
        );
    }
}
