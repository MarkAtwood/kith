use axum::extract::connect_info::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use kith_core::{Identity, Role};
use kith_events::EventSender;
use kith_store::Store;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::auth::WhoIsProvider;

/// Shared application state injected into every request via axum State.
///
/// Generic over `W` so that tests can substitute a `MockWhoIs` in place of
/// `LocalApiClient` without dynamic dispatch (which would require object-safe
/// async traits).  `Arc<W>` provides cheap clone and shared ownership.
///
/// `Store` is wrapped in `std::sync::Mutex` because `rusqlite::Connection`
/// is `!Sync` (contains `RefCell` internally).  The mutex is held only for
/// the synchronous part of authorization (one SQLite lookup), never across
/// an `.await`.  All JMAP handler crates (`kith-chat`, `kith-peer`) also
/// use `std::sync::Mutex<Store>`, so a single `Arc` can be shared.
pub struct AppState<W> {
    pub ts: Arc<W>,
    pub store: Arc<Mutex<Store>>,
    pub owner_id: String,
    /// Tailscale `LoginName` of the mailbox owner (e.g. `alice@example.com`).
    ///
    /// Populated at startup from the Tailscale LocalAPI WhoIs response for the
    /// owner's own tailnet address.  Falls back to an empty string when
    /// Tailscale is unavailable (development mode without tailscaled).
    pub owner_login: String,
    /// Base URL used in JMAP Session object URL fields (`apiUrl`, `downloadUrl`
    /// etc.).  Read once at startup from `KITHD_BASE_URL` (or the deprecated
    /// `KITH_BASE_URL`) and stored here so `session_handler` does not re-read
    /// the environment on every request.
    pub base_url: String,
    /// Broadcast sender for state-change notifications.  Handlers and the
    /// store layer use this to signal EventSource subscribers that a JMAP
    /// object type has advanced its state counter.
    pub events_tx: EventSender,
    /// Registered JMAP method dispatcher.  Shared across all request tasks.
    pub dispatcher: Arc<kith_jmap::Dispatcher>,
    /// On-disk blob store for attachment upload/download.
    pub blob_store: Arc<kith_attach::BlobStore>,
}

// Manual Clone so we don't require W: Clone -- Arc<W> is always Clone.
// `broadcast::Sender` is Clone (it is an Arc-wrapped channel handle).
impl<W> Clone for AppState<W> {
    fn clone(&self) -> Self {
        AppState {
            ts: Arc::clone(&self.ts),
            store: Arc::clone(&self.store),
            owner_id: self.owner_id.clone(),
            owner_login: self.owner_login.clone(),
            base_url: self.base_url.clone(),
            events_tx: self.events_tx.clone(),
            dispatcher: Arc::clone(&self.dispatcher),
            blob_store: Arc::clone(&self.blob_store),
        }
    }
}

/// Verified caller: role and identity extracted from WhoIs on every request.
///
/// Handlers receive this by placing it as a parameter.  The extractor runs
/// authorization once per request; handlers must not perform their own
/// ad-hoc identity checks.
#[derive(Debug, Clone)]
pub struct Caller {
    pub role: Role,
    pub identity: Identity,
}

impl<W> FromRequestParts<AppState<W>> for Caller
where
    W: WhoIsProvider + Send + Sync + 'static,
{
    type Rejection = CallerRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState<W>,
    ) -> Result<Self, Self::Rejection> {
        let ConnectInfo(addr) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map_err(|_| CallerRejection::Internal)?;

        // WhoIs is async.  We must complete it before acquiring the store lock
        // because `ContactStore<'_>` holds `&Connection` which is `!Send`, and
        // holding a `!Send` value across `.await` would make this future `!Send`
        // (violating the axum `FromRequestParts` contract).
        //
        // This replicates the logic of `authorize()` split into two phases:
        //   Phase 1 (async): WhoIs lookup -> Identity
        //   Phase 2 (sync):  contacts check inside a lock guard scope
        let who = state
            .ts
            .whois(addr)
            .await
            .map_err(|_| CallerRejection::Internal)?;

        let identity = Identity {
            user_id: who.user_profile.id,
            login_name: who.user_profile.login_name,
            display_name: who.user_profile.display_name,
            node_name: who.node.name,
        };

        // Hold the lock only for the synchronous contacts check; drop it before
        // returning so concurrent requests can proceed.
        //
        // `ContactStore<'_>` holds `&Connection` which is `!Send`, so we must
        // complete the async WhoIs call above before acquiring the lock -- holding
        // a `!Send` value across `.await` would make this future `!Send`.
        let role = {
            let store = state.store.lock().map_err(|_| CallerRejection::Internal)?;
            let contacts = store.contacts();
            crate::auth::classify(&identity, &contacts, &state.owner_id).map_err(|e| match e {
                kith_core::AuthError::Unauthorized => CallerRejection::Unauthorized,
                // classify() only returns Unauthorized or WhoIsFailed; the other
                // variants cannot arise here but are listed explicitly so adding a
                // new AuthError variant produces a compile error rather than a
                // silent behaviour change.
                kith_core::AuthError::WhoIsFailed(_)
                | kith_core::AuthError::NoPeerAddr
                | kith_core::AuthError::SenderMismatch => CallerRejection::Internal,
            })
        }?;

        Ok(Caller { role, identity })
    }
}

/// HTTP error responses for `Caller` extraction failures.
///
/// Error bodies must NOT include user IDs, peer addresses, or internal error
/// details -- only a stable machine-readable `type` field.
pub enum CallerRejection {
    Unauthorized,
    Internal,
}

impl IntoResponse for CallerRejection {
    fn into_response(self) -> Response {
        match self {
            CallerRejection::Unauthorized => {
                (StatusCode::UNAUTHORIZED, r#"{"type":"unauthorized"}"#).into_response()
            }
            CallerRejection::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"type":"serverFail"}"#,
            )
                .into_response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use kith_core::AuthError;
    use kith_tslocal::{UserProfile, WhoIsNode, WhoIsResponse};
    use tower::ServiceExt;

    // -----------------------------------------------------------------------
    // Local test double -- same shape as the one in auth.rs tests but
    // defined here independently so tests do not depend on private internals.
    // `Some(response)` -> Ok; `None` -> Err(WhoIsFailed("test")).
    // -----------------------------------------------------------------------
    struct MockWhoIs(Option<WhoIsResponse>);

    impl WhoIsProvider for MockWhoIs {
        fn whois(
            &self,
            _addr: SocketAddr,
        ) -> impl std::future::Future<Output = Result<WhoIsResponse, AuthError>> + Send {
            let result: Result<WhoIsResponse, AuthError> = match &self.0 {
                Some(r) => Ok(r.clone()),
                None => Err(AuthError::WhoIsFailed("test".into())),
            };
            async move { result }
        }
    }

    fn make_whois(id: &str, login: &str) -> WhoIsResponse {
        WhoIsResponse {
            node: WhoIsNode {
                name: "test-node".into(),
            },
            user_profile: UserProfile {
                id: id.into(),
                login_name: login.into(),
                display_name: None,
            },
        }
    }

    fn make_blob_store() -> (Arc<kith_attach::BlobStore>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("TempDir::new should succeed");
        let store = Arc::new(kith_attach::BlobStore::new(dir.path()));
        store.init().expect("blob store init must succeed");
        (store, dir)
    }

    fn make_state(whois: MockWhoIs, owner_id: &str) -> (AppState<MockWhoIs>, tempfile::TempDir) {
        let store = Arc::new(std::sync::Mutex::new(
            Store::open_in_memory().expect("in-memory store"),
        ));
        let (events_tx, _events_rx) = kith_events::make_channel(64);
        let (blob_store, blob_dir) = make_blob_store();
        let state = AppState {
            ts: Arc::new(whois),
            store,
            owner_id: owner_id.to_string(),
            owner_login: format!("{owner_id}@example.com"),
            base_url: crate::DEFAULT_BASE_URL.to_string(),
            events_tx,
            dispatcher: Arc::new(kith_jmap::Dispatcher::new()),
            blob_store,
        };
        (state, blob_dir)
    }

    /// Build a test router: one GET "/" that returns the caller's role as a
    /// plain text string.  Uses `AppState<MockWhoIs>` so no real tailscaled
    /// is needed.
    fn make_app(whois: MockWhoIs, owner_id: &str) -> (Router, tempfile::TempDir) {
        let (state, blob_dir) = make_state(whois, owner_id);
        let router = Router::new()
            .route(
                "/",
                get(|caller: Caller| async move { format!("{:?}", caller.role) }),
            )
            .with_state(state)
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));
        (router, blob_dir)
    }

    /// Add a contact to the store for tests that exercise the peer path.
    fn add_contact(store: &Arc<std::sync::Mutex<Store>>, user_id: &str, login: &str) {
        store
            .lock()
            .expect("store lock must not be poisoned")
            .contacts()
            .upsert(user_id, login, "peer-kith.tail.ts.net", None, 1000)
            .expect("upsert must succeed");
    }

    // -----------------------------------------------------------------------
    // extractor_owner_returns_caller_with_owner_role
    // Oracle: AppState has owner_id "uid-owner"; WhoIs returns "uid-owner" ->
    //         Caller{ role: Owner }.  Confirmed by checking response body.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn extractor_owner_returns_caller_with_owner_role() {
        let (app, _blob_dir) = make_app(
            MockWhoIs(Some(make_whois("uid-owner", "owner@example.com"))),
            "uid-owner",
        );

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            body_str.contains("Owner"),
            "expected role Owner in body, got: {body_str}"
        );
    }

    // -----------------------------------------------------------------------
    // extractor_peer_returns_caller_with_peer_role
    // Oracle: WhoIs returns "uid-bob" who is in contacts (unblocked) ->
    //         Caller{ role: Peer }.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn extractor_peer_returns_caller_with_peer_role() {
        let (state, _blob_dir) = make_state(
            MockWhoIs(Some(make_whois("uid-bob", "bob@example.com"))),
            "uid-owner",
        );
        add_contact(&state.store, "uid-bob", "bob@example.com");

        let app = Router::new()
            .route(
                "/",
                get(|caller: Caller| async move { format!("{:?}", caller.role) }),
            )
            .with_state(state)
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            body_str.contains("Peer"),
            "expected role Peer in body, got: {body_str}"
        );
    }

    // -----------------------------------------------------------------------
    // extractor_unknown_returns_401
    // Oracle: WhoIs returns "uid-stranger" not in contacts -> 401.
    //         Body must NOT contain the user_id (no PII leak).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn extractor_unknown_returns_401() {
        let (app, _blob_dir) = make_app(
            MockWhoIs(Some(make_whois("uid-stranger", "stranger@example.com"))),
            "uid-owner",
        );

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        assert!(
            !body_str.contains("uid-stranger"),
            "user_id must not appear in 401 body: {body_str}"
        );
        assert!(
            !body_str.contains("stranger@example.com"),
            "login must not appear in 401 body: {body_str}"
        );
    }

    // -----------------------------------------------------------------------
    // extractor_whois_fail_returns_500
    // Oracle: MockWhoIs(None) returns WhoIsFailed -> 500.
    //         Body must NOT contain the error detail string.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn extractor_whois_fail_returns_500() {
        let (app, _blob_dir) = make_app(MockWhoIs(None), "uid-owner");

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let body_str = std::str::from_utf8(&body).unwrap();
        // Must not leak internal error detail ("test" is the WhoIsFailed message)
        assert!(
            !body_str.contains("\"test\""),
            "error detail must not appear in 500 body: {body_str}"
        );
        assert!(
            body_str.contains("serverFail"),
            "expected serverFail type in body, got: {body_str}"
        );
    }

    // -----------------------------------------------------------------------
    // extractor_blocked_returns_401
    // Oracle: WhoIs returns "uid-bob" who IS in contacts but blocked=true -> 401.
    //         Verifies the extractor enforces the blocked flag, not just presence.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn extractor_blocked_returns_401() {
        let (state, _blob_dir) = make_state(
            MockWhoIs(Some(make_whois("uid-bob", "bob@example.com"))),
            "uid-owner",
        );
        // Add contact, then block them.
        add_contact(&state.store, "uid-bob", "bob@example.com");
        state
            .store
            .lock()
            .expect("store lock must not be poisoned")
            .contacts()
            .set_blocked("uid-bob", true)
            .expect("set_blocked must succeed");

        let app = Router::new()
            .route(
                "/",
                get(|caller: Caller| async move { format!("{:?}", caller.role) }),
            )
            .with_state(state)
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))));

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "blocked contact must be rejected with 401"
        );
    }

    // -----------------------------------------------------------------------
    // Verify AppState<LocalApiClient> compiles -- ensures the production type
    // satisfies all bounds (WhoIsProvider, Send, Sync, 'static).
    // This is a compile-time check only; the function is never called.
    // -----------------------------------------------------------------------
    #[allow(dead_code)]
    fn _assert_production_state_compiles() {
        use kith_tslocal::LocalApiClient;
        let _: fn() -> AppState<LocalApiClient> = || {
            let (events_tx, _events_rx) = kith_events::make_channel(64);
            let blob_dir = std::path::PathBuf::from("/tmp/kithd-blob");
            AppState {
                ts: Arc::new(LocalApiClient::new("/var/run/tailscale/tailscaled.sock")),
                store: Arc::new(std::sync::Mutex::new(Store::open_in_memory().unwrap())),
                owner_id: "uid".to_string(),
                owner_login: String::new(),
                base_url: crate::DEFAULT_BASE_URL.to_string(),
                events_tx,
                dispatcher: Arc::new(kith_jmap::Dispatcher::new()),
                blob_store: Arc::new(kith_attach::BlobStore::new(blob_dir)),
            }
        };
    }
}
