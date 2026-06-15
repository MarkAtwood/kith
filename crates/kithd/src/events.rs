use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
};
use kith_core::Role;
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

/// Parse a state token of the form `"s-<N>"` and return `N` as an `i64`.
///
/// Returns `None` if the string is not in the expected format or if the
/// numeric suffix does not parse as an `i64`.  Used for numeric comparison
/// during Last-Event-ID replay to avoid spurious replays when the server
/// state counter is behind the client's.
fn parse_state_counter(s: &str) -> Option<i64> {
    s.strip_prefix("s-").and_then(|n| n.parse().ok())
}

use kith_core::FederationTransport;
use crate::extractors::{AppState, Caller};

/// Query parameters accepted by the EventSource endpoint.
///
/// `types` is a comma-separated list of JMAP object type names to filter on.
/// Omitting it (or passing an empty string) means all types are delivered.
///
/// `closeafter` controls stream lifetime:
/// - `"state"` — deliver the first matching event then close the stream
///   (useful for polling clients that want at-most-one notification)
/// - `"no"` or absent — stream stays open until the client disconnects
///
/// `ping` — RFC 8620 §7.3 keepalive interval in seconds.  When present and
/// non-zero, the server sends an initial `ping` SSE event and uses the
/// supplied value as the SSE keepalive interval.  Values greater than 300
/// are clamped to 300; a value of 0 is treated as absent.
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub types: Option<String>,
    pub closeafter: Option<String>,
    pub ping: Option<u64>,
}

const KEEPALIVE_SECS: u64 = 15;
const PING_MAX_SECS: u64 = 300;

/// Compact filter for the three JMAP object types Kith exposes.
///
/// Bit layout: bit 0 = ChatContact, bit 1 = Chat, bit 2 = Message.
/// `None` means "no filter — allow all"; `Some(TypeFilter(bits))` means
/// only allow types whose bit is set.  Stored as a `u8` so that the live
/// stream closure captures a single `Copy` word instead of a heap-allocated
/// `Vec<String>`.
#[derive(Clone, Copy)]
struct TypeFilter(u8);

impl TypeFilter {
    const CHAT_CONTACT: u8 = 0b001;
    const CHAT: u8 = 0b010;
    const MESSAGE: u8 = 0b100;

    /// Parse a comma-separated type list into a `TypeFilter`.
    ///
    /// Returns `Ok(None)` for an empty string (meaning "all types").
    /// Returns `Err(())` if any token is not a recognised type name.
    fn parse(s: &str) -> Result<Option<Self>, ()> {
        if s.is_empty() {
            return Ok(None);
        }
        let mut bits: u8 = 0;
        for token in s.split(',').map(str::trim) {
            match token {
                "ChatContact" => bits |= Self::CHAT_CONTACT,
                "Chat" => bits |= Self::CHAT,
                "Message" => bits |= Self::MESSAGE,
                _ => return Err(()),
            }
        }
        debug_assert!(
            bits != 0,
            "TypeFilter::parse: zero bitmask from non-empty input"
        );
        Ok(Some(TypeFilter(bits)))
    }

    fn allows(self, type_name: &str) -> bool {
        match type_name {
            "ChatContact" => self.0 & Self::CHAT_CONTACT != 0,
            "Chat" => self.0 & Self::CHAT != 0,
            "Message" => self.0 & Self::MESSAGE != 0,
            // Unknown type names are dropped.  TypeFilter::parse() rejects
            // unknown names at the query parameter level, so this arm is only
            // reachable via broadcast events from a new store type.  Warn in
            // release builds so the omission is visible in logs.
            _ => {
                tracing::warn!(
                    type_name,
                    "TypeFilter::allows: unknown type — add a match arm for every type emitted by the store"
                );
                false
            }
        }
    }
}

/// SSE endpoint for JMAP state-change push notifications.
///
/// Only [`Role::Owner`] callers may connect.  Peer callers receive 403.
///
/// The stream emits `event: state` frames whose `data` is a JSON object
/// with the same shape as a JMAP `StateChange` push:
///
/// ```json
/// {"changed":{"a-self":{"Message":"s-42"}}}
/// ```
///
/// If the broadcast receiver falls behind (messages are dropped), the gap
/// is logged and skipped; the client must resync via `<Type>/changes`.
pub async fn events_handler<T: FederationTransport>(
    caller: Caller,
    State(state): State<AppState<T>>,
    Query(params): Query<EventsQuery>,
    headers: HeaderMap,
) -> Response {
    // Auth check first — before any resource allocation.
    if caller.role != Role::Owner {
        return (StatusCode::FORBIDDEN, r#"{"type":"forbidden"}"#).into_response();
    }

    // Validate closeafter before subscribing.
    let close_after_first = match params.closeafter.as_deref() {
        None | Some("no") => false,
        Some("state") => true,
        Some(_) => {
            return (StatusCode::BAD_REQUEST, r#"{"type":"invalidArguments"}"#).into_response();
        }
    };

    // Validate and normalise ping interval.
    // ping=0 is treated as absent; values > PING_MAX_SECS are clamped.
    let ping_secs: Option<u64> = match params.ping {
        None | Some(0) => None,
        Some(n) => Some(n.min(PING_MAX_SECS)),
    };

    // Parse and validate types filter before subscribing.
    let type_filter: Option<TypeFilter> = match params.types.as_deref() {
        None | Some("") => None,
        Some(t) => match TypeFilter::parse(t) {
            Ok(f) => f,
            Err(()) => {
                return (StatusCode::BAD_REQUEST, r#"{"type":"invalidArguments"}"#).into_response();
            }
        },
    };

    // Extract and validate Last-Event-ID.  Invalid values (wrong format or
    // longer than 64 bytes) are silently treated as absent — no 400 error.
    // Valid format is "s-" followed by one or more ASCII digits.
    let last_event_id: Option<String> = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            if s.len() > 64 {
                return None;
            }
            let suffix = s.strip_prefix("s-")?;
            if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
                Some(s.to_string())
            } else {
                None
            }
        });

    // Subscribe FIRST, before reading store state.  Any state change that
    // arrives between subscription and the state read below will be delivered
    // via the live stream, so no events are lost.
    let mut rx = state.events_tx.subscribe();

    // Build the initial events to deliver at the start of the stream.
    //
    // Order: ping event (if requested) comes first, then any LEI replay
    // events.  This guarantees the client sees the ping acknowledgement
    // before any state notifications, as required by RFC 8620 §7.3.
    let mut replay_events: Vec<Result<Event, Infallible>> = Vec::new();

    if let Some(n) = ping_secs {
        let data = serde_json::json!({ "interval": n }).to_string();
        replay_events.push(Ok(Event::default().event("ping").data(data)));
    }

    // Append LEI replay events if the client supplied a valid Last-Event-ID.
    // We lock the store, read all three state tokens in one query, then
    // release the lock before any async work.
    //
    // Replay design note: the client sends a single Last-Event-ID token
    // (e.g. "s-5"), which is the state token from the last SSE event it
    // received — not a per-type cursor.  That single value is compared
    // independently against each type's current state.  A type is replayed
    // when server_n >= lei_n (strictly ahead OR equal-counter).
    //
    // Equal-counter replay: per-type counters are independent.  If Chat is at
    // s-5 and the client's LEI is s-5 from a Message event, the client may
    // never have received a Chat event at s-5.  Replaying when server_n ==
    // lei_n sends one extra SSE event; the client calls Chat/changes with
    // sinceState=s-4 and gets the delta.  The worst case (client already has
    // s-5) is one spurious no-op changes round-trip — correct and safe.
    // Suppressing (server_n < lei_n only) risks silent data loss if the
    // client missed an event for a type whose counter equals the LEI.
    if let Some(ref lei) = last_event_id {
        let type_states: [(&str, String); 3] = {
            let store = match state.store.lock() {
                Ok(g) => g,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"type":"serverFail"}"#,
                    )
                        .into_response();
                }
            };
            // Single query fetches contact, chat, and message counters at once.
            match store.get_all_states() {
                Ok(states) => states,
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        r#"{"type":"serverFail"}"#,
                    )
                        .into_response();
                }
            }
        };

        let state_replays: Vec<Result<Event, Infallible>> = type_states
            .into_iter()
            .filter_map(|(type_name, current_state)| {
                // Apply the types filter the same way the live stream does.
                if let Some(filter) = type_filter {
                    if !filter.allows(type_name) {
                        return None;
                    }
                }
                // Replay only if the server counter is strictly ahead of the
                // client's LEI counter.  String equality is insufficient:
                // "s-3" != "s-5" but the client is *ahead* of the server, so
                // replaying would send stale data.  Numeric comparison is the
                // correct guard.
                //
                // unwrap_or semantics: server state always has valid "s-N"
                // format (produced by format!("s-{counter}")), so 0 is a safe
                // fallback.  A malformed server counter is treated as 0 (start
                // of time), which means server_n <= lei_n for any non-negative
                // LEI and replay is suppressed — the conservative safe default.
                // LEI from an attacker-controlled header is treated as i64::MAX
                // (far ahead) to skip replay safely when the header is
                // malformed.
                let server_n = parse_state_counter(&current_state).unwrap_or(0);
                let lei_n = parse_state_counter(lei).unwrap_or(i64::MAX);
                // Replay when server is at or ahead of LEI: includes equal-counter
                // case to avoid silent missed-event for types that share a counter
                // value with the LEI from a different type's event.
                if server_n < lei_n {
                    return None;
                }
                let data = serde_json::json!({
                    "changed": { "a-self": { type_name: &current_state } }
                })
                .to_string();
                Some(Ok(Event::default()
                    .event("state")
                    .data(data)
                    .id(&current_state)))
            })
            .collect();
        replay_events.extend(state_replays);
    }

    // Spawn a task that coalesces rapid-fire StateChange events into single
    // SSE frames.  The task owns the broadcast receiver and drives a Tokio
    // mpsc channel whose receiving end becomes the live stream.
    //
    // Coalescing rationale: store writes are synchronous, so all StateChange
    // events emitted by a single JMAP method call (e.g. Peer/deliver touching
    // Contact + Chat + Message) are queued before any async yield.  After the
    // first recv().await unblocks, try_recv() captures all of them without
    // sleeping, producing one merged SSE frame instead of three.
    //
    // Bounded channel: a stalled SSE consumer (slow/disconnected client) must
    // not cause unbounded memory growth.  Capacity 256 is well above the burst
    // of any realistic JMAP workload (3 types × burst factor).  The coalescing
    // task uses try_send; if the channel is full the connection is dropped and
    // the client can reconnect.  Blocking here would stall the broadcast
    // receiver, causing other clients to see Lagged errors as the ring buffer
    // fills.
    //
    // Channel item is `Option<Result<Event, Infallible>>`:
    //   Some(event) — a real SSE event to forward to the client.
    //   None        — close-signal: the live_stream must stop.
    //
    // `None` is only sent when `close_after_first` is true AND the batch was
    // entirely filtered out by the type filter.  It allows `closeafter=state`
    // to terminate the SSE connection even when no type-matching event was
    // present in the live broadcast batch.
    let (live_tx, live_rx) = tokio::sync::mpsc::channel::<Option<Result<Event, Infallible>>>(256);
    // "peer" in Kith is a remote kith user; this is the owner's client node.
    // node_name is the MagicDNS hostname; may be empty on bare Headscale — fall
    // back to display() (login_name or user_id) so the log is always actionable.
    let client_node = if caller.identity.node_name.is_empty() {
        caller.identity.display().to_owned()
    } else {
        caller.identity.node_name.clone()
    };

    tokio::spawn(async move {
        // Reuse one HashMap across loop iterations to avoid per-batch allocation.
        // Three JMAP types (Contact, Chat, Message) are the only possible keys.
        let mut batch: HashMap<String, String> = HashMap::with_capacity(3);

        // Helper: insert sc into batch if it passes the type filter.
        // Defined once outside the loop; type_filter is Copy so the capture
        // does not prevent the closure from being called repeatedly.
        let insert_if_allowed =
            |batch: &mut HashMap<String, String>, type_name: String, new_state: String| {
                if let Some(filter) = type_filter {
                    if !filter.allows(&type_name) {
                        return;
                    }
                }
                batch.insert(type_name, new_state);
            };

        loop {
            // Wait for the first available StateChange in this batch,
            // or for the client to disconnect (live_tx.closed()).
            let first = tokio::select! {
                result = rx.recv() => match result {
                    Ok(sc) => sc,
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!(
                            dropped = n,
                            "SSE receiver lagged; client must resync via /changes"
                        );
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                },
                _ = live_tx.closed() => break,
            };

            // Merge this batch into the reused map.
            // Later values for the same type overwrite earlier ones (last write wins).
            batch.clear();

            insert_if_allowed(&mut batch, first.type_name, first.new_state);

            // Drain all immediately available events without blocking.
            //
            // TryRecvError::Closed means the buffer is empty AND all senders
            // are gone.  Treat it like Empty: break and emit what we have.
            // The outer recv().await will then see Closed and exit the loop.
            loop {
                match rx.try_recv() {
                    Ok(sc) => {
                        insert_if_allowed(&mut batch, sc.type_name, sc.new_state);
                    }
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                        tracing::warn!(
                            dropped = n,
                            "SSE receiver lagged during drain; client must resync via /changes"
                        );
                        // Continue draining — more messages may follow.
                    }
                    Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                        // Buffer exhausted and all senders gone — emit the
                        // current batch and let the outer loop exit cleanly.
                        break;
                    }
                }
            }

            // If the filter removed every event in the batch and closeafter=state
            // is active, send a None close-signal so the stream terminates even
            // though no type-matching content was produced.  Without this, the
            // take(N) combinator would wait forever for a live item that never
            // arrives when all broadcasts are type-filtered.
            if batch.is_empty() {
                if close_after_first {
                    match live_tx.try_send(None) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                client = %client_node,
                                "SSE client channel full while sending close-signal; \
                                 dropping stalled connection"
                            );
                            break;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                    }
                } else if live_tx.is_closed() {
                    // Belt-and-suspenders: if select! picked the rx.recv() arm while
                    // live_tx.closed() was simultaneously ready (pseudorandom selection),
                    // the batch is filtered to empty here.  is_closed() catches that case.
                    // In the single-threaded test runtime this path is unreachable because
                    // closed() always fires on the next tick; in production both branches
                    // can fire.
                    break;
                }
                // close_after_first=false + empty batch: no event to send, but check
                // whether the receiver is still alive so we don't loop forever if the
                // client disconnected while only filtered-out event types are active.
                continue;
            }

            // Compute the SSE event id: highest numeric suffix across all
            // state tokens in this batch.  State tokens are "s-N"; parse N
            // and take the max, then re-format as "s-{max}".
            let max_n: i64 = batch
                .values()
                .filter_map(|s| s.strip_prefix("s-").and_then(|n| n.parse::<i64>().ok()))
                .max()
                .unwrap_or(0); // unwrap_or: batch is non-empty but may lack "s-N" tokens
            let event_id = format!("s-{max_n}");

            let data = serde_json::json!({
                "changed": { "a-self": batch }
            })
            .to_string();

            let event = Event::default().event("state").data(data).id(event_id);

            // try_send: if the channel is full (stalled consumer) or closed
            // (disconnected client), drop the connection immediately.  A stalled
            // consumer must not block the coalescing task, which holds the
            // broadcast::Receiver; blocking here would starve all other sends.
            match live_tx.try_send(Some(Ok(event))) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        client = %client_node,
                        "SSE client channel full; dropping stalled connection"
                    );
                    break;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
            }
        }
    });

    // The live stream carries Option items: Some(event) is forwarded;
    // None is a close-signal that terminates the stream.
    let live_stream = ReceiverStream::new(live_rx)
        .take_while(|item| item.is_some())
        .map(|item| item.expect("Some guaranteed by take_while"));

    // Replay events are delivered first; the live stream follows.
    //
    // We track two counts before the Vec is moved into the stream:
    //
    //   ping_offset        — 1 if a ping event was prepended, else 0.
    //   state_replay_count — number of actual state replay events (excluding
    //                        the ping).
    //
    // The separation is required for correct closeafter=state behaviour: the
    // ping event must not be counted as a "state replay" for the purpose of
    // deciding whether a live event is still needed.
    let ping_offset: usize = if ping_secs.is_some() { 1 } else { 0 };
    let state_replay_count = replay_events.len() - ping_offset;
    let stream = tokio_stream::iter(replay_events).chain(live_stream);

    let keepalive_interval = Duration::from_secs(ping_secs.unwrap_or(KEEPALIVE_SECS));

    // The two branches produce distinct concrete stream types (Take<…> vs
    // the base Chain stream), so we call .into_response() on each branch
    // rather than trying to unify them behind a box.
    if close_after_first {
        // Deliver all pending replay events (ping + state), then at most one
        // live event.
        //
        // live_limit is based on state_replay_count only — a ping event must
        // not suppress the wait for a live state event.
        //
        // When state_replay_count > 0: pending state exists — deliver all
        // replay events and close without waiting for a live event.
        // When state_replay_count == 0: no state replays — deliver any ping
        // first, then wait for exactly one live state event (live_limit = 1).
        let live_limit = if state_replay_count > 0 { 0 } else { 1 };
        Sse::new(stream.take(ping_offset + state_replay_count + live_limit))
            .keep_alive(KeepAlive::new().interval(keepalive_interval))
            .into_response()
    } else {
        Sse::new(stream)
            .keep_alive(KeepAlive::new().interval(keepalive_interval))
            .into_response()
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
    use kith_core::{AuthError, ConnectionContext, FederationTransport, Identity, IdentityProvider, StateChange};
    use kith_events::make_channel;
    use kith_store::Store;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    struct MockTransport(Option<Identity>);

    impl IdentityProvider for MockTransport {
        fn identify_caller(
            &self,
            _ctx: &ConnectionContext,
        ) -> impl std::future::Future<Output = Result<Identity, AuthError>> + Send + '_ {
            let result: Result<Identity, AuthError> = match &self.0 {
                Some(id) => Ok(id.clone()),
                None => Err(AuthError::WhoIsFailed("test".into())),
            };
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
        Identity::new(id.into(), login.into(), None, "test-node".into())
    }

    fn make_blob_store_for_events_tests() -> std::sync::Arc<kith_attach::BlobStore> {
        let dir = std::env::temp_dir().join(format!(
            "kithd-events-test-{}",
            kith_attach::BlobStore::generate_blob_id()
        ));
        let store = std::sync::Arc::new(kith_attach::BlobStore::new(&dir));
        store.init().expect("blob store init must succeed");
        store
    }

    fn make_state(transport: MockTransport, owner_id: &str) -> AppState<MockTransport> {
        let store = Arc::new(Mutex::new(
            Store::open_in_memory().expect("in-memory store"),
        ));
        let (events_tx, _events_rx) = make_channel(std::num::NonZeroUsize::new(64).unwrap());
        AppState {
            transport: Arc::new(transport),
            store,
            owner_id: owner_id.to_string(),
            owner_login: format!("{owner_id}@example.com"),
            base_url: crate::DEFAULT_BASE_URL.to_string(),
            events_tx,
            dispatcher: Arc::new(kith_jmap::Dispatcher::new()),
            blob_store: make_blob_store_for_events_tests(),
        }
    }

    fn make_app(state: AppState<MockTransport>) -> Router {
        Router::new()
            .route("/jmap/events", get(events_handler::<MockTransport>))
            .with_state(state)
            .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 9999))))
    }

    // -----------------------------------------------------------------------
    // events_peer_forbidden
    // Oracle: A caller identified as Peer (in contacts) requests /jmap/events.
    //         Must receive 403; EventSource is Owner-only.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_peer_forbidden() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-bob", "bob@example.com"))),
            "uid-owner",
        );
        // Register uid-bob as a permitted contact so they get Role::Peer (not 401).
        state
            .store
            .lock()
            .expect("store lock must not be poisoned")
            .contacts()
            .upsert(
                "uid-bob",
                "bob@example.com",
                "bob-kith.tail.ts.net",
                None,
                1000,
            )
            .expect("upsert must succeed");

        let app = make_app(state);
        let req = Request::builder()
            .uri("/jmap/events")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Peer must receive 403 on EventSource"
        );
    }

    // -----------------------------------------------------------------------
    // events_bad_closeafter_rejected
    // Oracle: closeafter=invalid is not in {"state","no"} — must return 400.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_bad_closeafter_rejected() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let app = make_app(state);
        let req = Request::builder()
            .uri("/jmap/events?closeafter=invalid")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "invalid closeafter must return 400"
        );
    }

    // -----------------------------------------------------------------------
    // events_bad_type_rejected
    // Oracle: types=UnknownType is not in VALID_TYPES — must return 400.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_bad_type_rejected() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let app = make_app(state);
        let req = Request::builder()
            .uri("/jmap/events?types=UnknownType")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "unknown type name must return 400"
        );
    }

    // -----------------------------------------------------------------------
    // events_owner_gets_sse_stream
    // Oracle: Owner requests /jmap/events with no filters → 200 with
    //         Content-Type: text/event-stream.  Stream stays open.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_owner_gets_sse_stream() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let app = make_app(state);
        let req = Request::builder()
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
            "expected text/event-stream content-type, got: {ct}"
        );
    }

    // -----------------------------------------------------------------------
    // events_closeafter_state_delivers_one_event
    // Oracle: closeafter=state → stream emits one event then closes.
    //         We send one StateChange on the broadcast channel and confirm
    //         exactly one SSE frame arrives in the response body.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_closeafter_state_delivers_one_event() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        // Send a StateChange before the handler subscribes; the handler will
        // subscribe to the broadcast, so we send after connecting by holding
        // the tx and using a task.
        let tx = state.events_tx.clone();
        let app = make_app(state);

        // Spawn a task that sends one event shortly after the handler subscribes.
        tokio::spawn(async move {
            // Small yield to let the handler subscribe first.
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Message", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Collect the body; with closeafter=state the stream ends after one event.
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Must contain exactly one "event: state" line.
        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "closeafter=state must deliver exactly one event, got body: {body:?}"
        );
        // Data must contain the type name and state token.
        assert!(
            body.contains("Message"),
            "event data must include type name"
        );
        assert!(body.contains("s-1"), "event data must include state token");
    }

    // -----------------------------------------------------------------------
    // events_type_filter_drops_non_matching
    // Oracle: types=Chat filter → Message events must not appear in stream.
    //         We use closeafter=state with types=Chat, send a Message event
    //         first (should be dropped), then a Chat event (should arrive).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_type_filter_drops_non_matching() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            // Send a Message event (should be filtered out).
            let _ = tx.send(StateChange::new("Message", "s-bad".to_string()));
            // Send a Chat event (should pass the filter and close the stream).
            let _ = tx.send(StateChange::new("Chat", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?types=Chat&closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        assert!(
            !body.contains("s-bad"),
            "Message event must be filtered out, got body: {body:?}"
        );
        assert!(
            body.contains("Chat"),
            "Chat event must appear in body, got body: {body:?}"
        );
        assert!(
            body.contains("s-1"),
            "Chat state token must appear in body, got body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // events_last_event_id_invalid_format_ignored
    // Oracle: RFC 8895 / SSE spec says a client MAY send Last-Event-ID.
    //         A value that doesn't match our "s-\d+" format must be silently
    //         ignored (no 400) and the stream must still open with 200.
    //         We use closeafter=state and a live event to prove the stream
    //         is functional despite the bad header.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_last_event_id_invalid_format_ignored() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Message", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .header("last-event-id", "garbage-not-a-state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "invalid Last-Event-ID must not cause a 400"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            body.contains("s-1"),
            "stream must still deliver events after invalid LEI is ignored, body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // events_last_event_id_too_long_ignored
    // Oracle: A Last-Event-ID value longer than 64 bytes must be silently
    //         ignored (no 400) per our validation rules.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_last_event_id_too_long_ignored() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Chat", "s-99".to_string()));
        });

        // 65-byte value that otherwise looks like a valid prefix
        let long_lei = format!("s-{}", "1".repeat(63));
        assert!(long_lei.len() > 64);
        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .header("last-event-id", long_lei.as_str())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "over-length Last-Event-ID must not cause a 400"
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();
        assert!(
            body.contains("s-99"),
            "stream must still deliver events, body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // events_last_event_id_replay_on_state_advance
    // Oracle: Client sends Last-Event-ID "s-0".  We advance Message state to
    //         "s-1" in the store before connecting.  The handler must
    //         immediately replay state events for all three types (Contact,
    //         Chat, Message) whose server_n >= lei_n=0, including those still
    //         at s-0 (equal-counter replay prevents silent missed events).
    //         closeafter=state causes the stream to close after the replays.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_last_event_id_replay_on_state_advance() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );

        // Advance only the Message state counter to "s-1".
        state
            .store
            .lock()
            .expect("store lock must not be poisoned")
            .messages()
            .advance_state()
            .expect("advance_state must succeed");

        let app = make_app(state);

        // No live event needed — the replay must provide it.
        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .header("last-event-id", "s-0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        let event_count = body.lines().filter(|l| *l == "event: state").count();
        // Three types (Contact, Chat, Message) all have server_n >= lei_n=0.
        assert_eq!(
            event_count, 3,
            "all three types must replay when server_n >= lei_n, got body: {body:?}"
        );
        assert!(
            body.contains("Message"),
            "replay must include the advanced Message type, body: {body:?}"
        );
        assert!(
            body.contains("s-1"),
            "replay must carry Message's current state token, body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // events_last_event_id_no_replay_when_client_ahead
    // Oracle: Client sends Last-Event-ID "s-2" but all types are still at
    //         "s-0" (server_n < lei_n for all types).  No replay event must
    //         be emitted.  We use a live broadcast event to close the stream
    //         so we can read the body and confirm no extra "event: state"
    //         line appeared before it.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_last_event_id_no_replay_when_client_ahead() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        // State is still "s-0" for all types; send one live event to close
        // the stream and give us a body to inspect.
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("ChatContact", "s-1".to_string()));
        });

        // LEI "s-2" is ahead of every type's server counter (all at s-0):
        // server_n=0 < lei_n=2 → no replay for any type.
        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .header("last-event-id", "s-2")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Exactly one event: the live ChatContact event, no spurious replays.
        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "no replay when client is ahead of server, got body: {body:?}"
        );
        assert!(
            body.contains("ChatContact"),
            "the live event must appear, body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // events_two_clients_both_receive_broadcast
    // Oracle: tokio broadcast channel semantics guarantee that every active
    //         subscriber receives every message.  Two concurrent SSE connections
    //         both subscribing before the broadcast is sent must each receive
    //         the state event.  We use closeafter=state so both futures
    //         terminate with a readable body.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_two_clients_both_receive_broadcast() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        let req_a = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .body(Body::empty())
            .unwrap();
        let req_b = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .body(Body::empty())
            .unwrap();

        // Both handlers subscribe when they start executing.  Spawn the
        // broadcast sender as a background task that yields first so both
        // handlers have time to subscribe before the message is sent.
        tokio::spawn(async move {
            // Yield enough times to let both handlers subscribe before we send.
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            let _ = tx.send(StateChange::new("Message", "s-42".to_string()));
        });

        let (resp_a, resp_b) = tokio::join!(app.clone().oneshot(req_a), app.oneshot(req_b),);

        let body_a_bytes = axum::body::to_bytes(resp_a.unwrap().into_body(), 4096)
            .await
            .unwrap();
        let body_b_bytes = axum::body::to_bytes(resp_b.unwrap().into_body(), 4096)
            .await
            .unwrap();
        let body_a = std::str::from_utf8(&body_a_bytes).unwrap();
        let body_b = std::str::from_utf8(&body_b_bytes).unwrap();

        // Both connections must see exactly one state event each.
        let count_a = body_a.lines().filter(|l| *l == "event: state").count();
        let count_b = body_b.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            count_a, 1,
            "client A must receive exactly one event, body: {body_a:?}"
        );
        assert_eq!(
            count_b, 1,
            "client B must receive exactly one event, body: {body_b:?}"
        );

        // Both must contain the broadcast state token (independent oracle:
        // the value was hardcoded above, not derived from the implementation).
        assert!(
            body_a.contains("s-42"),
            "client A must see state s-42, body: {body_a:?}"
        );
        assert!(
            body_b.contains("s-42"),
            "client B must see state s-42, body: {body_b:?}"
        );
    }

    // -----------------------------------------------------------------------
    // events_last_event_id_replays_at_equal_counter
    // Oracle: When the client's Last-Event-ID equals a type's current state,
    //         replay IS emitted for that type.  Per-type counters are
    //         independent: LEI "s-1" from a Contact event does not guarantee
    //         the client received a Message event also at counter 1.
    //         We advance Message to "s-1" then reconnect with LEI "s-1" and
    //         types=Message.  A replay of Message "s-1" is emitted (1 event)
    //         and closeafter=state closes the stream before the live "s-2"
    //         broadcast fires.  The body must contain "s-1" and NOT "s-2".
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_last_event_id_replays_at_equal_counter() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );

        // Advance Message state to "s-1" — this is the LEI the client will send.
        state
            .store
            .lock()
            .expect("store lock must not be poisoned")
            .messages()
            .advance_state()
            .expect("advance_state must succeed");

        let tx = state.events_tx.clone();
        let app = make_app(state);

        // Broadcast a live Message event at "s-2" to close the stream.
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Message", "s-2".to_string()));
        });

        // Reconnect with LEI = "s-1" (the state we already have).
        let req = Request::builder()
            .uri("/jmap/events?types=Message&closeafter=state")
            .header("last-event-id", "s-1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Exactly one event: the "s-1" replay.  closeafter=state with 1
        // replay event suppresses the live "s-2" broadcast (live_limit=0).
        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "must have exactly one event (s-1 replay), body: {body:?}"
        );
        assert!(
            body.contains("\"s-1\""),
            "equal-counter replay must appear, body: {body:?}"
        );
        assert!(
            !body.contains("\"s-2\""),
            "live s-2 must not appear (stream closed by replay), body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // coalesce_message_and_chat_produce_one_sse_frame
    // Oracle: RFC 8620 §7.3 — a StateChange push object's `changed` map MUST
    //         contain all types that changed, keyed by accountId "a-self".
    //         Two sends with no yield between them (Message "s-42" then Chat
    //         "s-1") must coalesce into a single SSE frame containing both:
    //           {"changed":{"a-self":{"Message":"s-42","Chat":"s-1"}}}
    //         The hardcoded state tokens are the independent oracle; their
    //         values are not derived from running the implementation.
    //
    //         Without coalescing: two separate frames are emitted, take(1)
    //         returns only the first frame, and the Chat assertion fails.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn coalesce_message_and_chat_produce_one_sse_frame() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            // Two sends with no await between them — both must land in the
            // broadcast ring buffer before the coalescing task can run.
            let _ = tx.send(StateChange::new("Message", "s-42".to_string()));
            let _ = tx.send(StateChange::new("Chat", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Exactly one SSE frame (coalesced), not two.
        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "Message+Chat simultaneous sends must coalesce into one SSE frame, got body: {body:?}"
        );

        // Parse the single data line and check the RFC 8620 §7.3 shape.
        // Oracle: expected values are "s-42" and "s-1" — hardcoded above.
        let data_line = body
            .lines()
            .find(|l| l.starts_with("data:"))
            .expect("must have a data line");
        let json_str = data_line.strip_prefix("data:").unwrap_or(data_line).trim();
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).expect("data must be valid JSON");
        let changed = &parsed["changed"]["a-self"];
        assert_eq!(
            changed["Message"].as_str(),
            Some("s-42"),
            "coalesced frame must contain Message→s-42, got: {parsed}"
        );
        assert_eq!(
            changed["Chat"].as_str(),
            Some("s-1"),
            "coalesced frame must contain Chat→s-1, got: {parsed}"
        );
    }

    // -----------------------------------------------------------------------
    // coalesce_single_send_produces_one_sse_frame
    // Oracle: RFC 8620 §7.3 — one StateChange event arriving alone must
    //         produce exactly one SSE frame containing only that type.
    //         Expected data: {"changed":{"a-self":{"Message":"s-7"}}}
    //         The Chat field must be absent: the frame must not contain
    //         keys for types that were not in the batch.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn coalesce_single_send_produces_one_sse_frame() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Message", "s-7".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "single send must produce exactly one SSE frame, got body: {body:?}"
        );

        let data_line = body
            .lines()
            .find(|l| l.starts_with("data:"))
            .expect("must have a data line");
        let json_str = data_line.strip_prefix("data:").unwrap_or(data_line).trim();
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).expect("data must be valid JSON");
        let changed = &parsed["changed"]["a-self"];

        // Oracle: "s-7" is the hardcoded value sent above.
        assert_eq!(
            changed["Message"].as_str(),
            Some("s-7"),
            "single-event frame must contain Message→s-7, got: {parsed}"
        );
        // Chat was not sent — must be absent from the changed map.
        assert!(
            changed.get("Chat").is_none() || changed["Chat"].is_null(),
            "single-event frame must not contain Chat, got: {parsed}"
        );
    }

    // -----------------------------------------------------------------------
    // coalesce_type_filter_excludes_chat_from_coalesced_frame
    // Oracle: RFC 8620 §7.3 + EventSource filter semantics — when types=Message
    //         is active, Chat events must be excluded even when they arrive
    //         in the same batch (no yield between sends).
    //         We send Message "s-42" and Chat "s-1" back-to-back.
    //         Expected coalesced frame: {"changed":{"a-self":{"Message":"s-42"}}}
    //         Chat must not appear; the frame still has exactly one SSE line.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn coalesce_type_filter_excludes_chat_from_coalesced_frame() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            // Both sends without yielding — Chat must be excluded by the
            // Message-only filter during coalescing, not reach the output.
            let _ = tx.send(StateChange::new("Message", "s-42".to_string()));
            let _ = tx.send(StateChange::new("Chat", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?types=Message&closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "types=Message filter must produce exactly one SSE frame, got body: {body:?}"
        );

        let data_line = body
            .lines()
            .find(|l| l.starts_with("data:"))
            .expect("must have a data line");
        let json_str = data_line.strip_prefix("data:").unwrap_or(data_line).trim();
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).expect("data must be valid JSON");
        let changed = &parsed["changed"]["a-self"];

        // Oracle: "s-42" was hardcoded above as the Message state.
        assert_eq!(
            changed["Message"].as_str(),
            Some("s-42"),
            "filtered frame must contain Message→s-42, got: {parsed}"
        );
        // Chat was sent but must be absent — filtered out before coalescing.
        assert!(
            changed.get("Chat").is_none() || changed["Chat"].is_null(),
            "Chat must be absent from types=Message filtered coalesced frame, got: {parsed}"
        );
    }

    // -----------------------------------------------------------------------
    // events_stranger_gets_401
    // Oracle: A caller whose Tailscale identity is neither the owner nor in
    //         contacts receives HTTP 401 — the same rejection as any other
    //         protected endpoint.  The Caller extractor runs before
    //         events_handler, so the events endpoint must be unreachable to
    //         strangers, not merely returning 403.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_stranger_gets_401() {
        // Stranger is not the owner and NOT in contacts.
        let state = make_state(
            MockTransport(Some(make_identity(
                "uid-stranger",
                "stranger@example.com",
            ))),
            "uid-owner",
        );
        let app = make_app(state);
        let req = Request::builder()
            .uri("/jmap/events")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "unknown caller must receive 401 on /jmap/events"
        );
    }

    // -----------------------------------------------------------------------
    // events_last_event_id_types_filter_applies_to_replay
    // Oracle: Client sends Last-Event-ID "s-0" and types=Message.  We
    //         advance both Chat ("s-1") and Message ("s-1") in the store.
    //         Only the Message replay must appear; Chat must be suppressed.
    //         closeafter=state closes after the single replay event.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_last_event_id_types_filter_applies_to_replay() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );

        {
            let store = state.store.lock().expect("store lock must not be poisoned");
            store.chats().advance_state().expect("advance Chat state");
            store
                .messages()
                .advance_state()
                .expect("advance Message state");
        }

        let app = make_app(state);

        let req = Request::builder()
            .uri("/jmap/events?types=Message&closeafter=state")
            .header("last-event-id", "s-0")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        assert!(
            !body.contains("Chat"),
            "Chat replay must be suppressed by types filter, body: {body:?}"
        );
        assert!(
            body.contains("Message"),
            "Message replay must appear, body: {body:?}"
        );

        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "exactly one event (Message replay) expected, body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // events_coalesce_multi_type_batch
    // Oracle: Three StateChange events (ChatContact s-1, Chat s-2, Message s-42)
    //         are queued into the broadcast channel before the background task
    //         can process them.  The coalescing loop must merge them into a
    //         single SSE frame containing all three types and use the highest
    //         state version (s-42) as the event id.
    //
    // We force coalescing by sending all three events synchronously before
    // yielding, then subscribe with closeafter=state so the stream closes
    // after exactly one emitted frame, letting us read the body.
    //
    // The single-frame constraint is the key assertion: if coalescing fails,
    // three separate frames would be emitted and closeafter=state would only
    // return the first one (ChatContact s-1), causing the Chat and Message
    // assertions to fail.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_coalesce_multi_type_batch() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            // Yield once so the handler's background task subscribes to the
            // broadcast before we send.
            tokio::task::yield_now().await;

            // Send all three events back-to-back without yielding between
            // them.  They land in the broadcast ring buffer synchronously.
            // The task's recv().await picks up the first, then try_recv()
            // captures the remaining two before any async yield — one batch.
            let _ = tx.send(StateChange::new("ChatContact", "s-1".to_string()));
            let _ = tx.send(StateChange::new("Chat", "s-2".to_string()));
            let _ = tx.send(StateChange::new("Message", "s-42".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Exactly one SSE frame must have been emitted.
        let event_count = body.lines().filter(|l| *l == "event: state").count();
        assert_eq!(
            event_count, 1,
            "three coalesced events must produce exactly one SSE frame, got body: {body:?}"
        );

        // All three type names must appear in the single coalesced data field.
        assert!(
            body.contains("ChatContact"),
            "coalesced frame must include ChatContact, body: {body:?}"
        );
        assert!(
            body.contains("Chat"),
            "coalesced frame must include Chat, body: {body:?}"
        );
        assert!(
            body.contains("Message"),
            "coalesced frame must include Message, body: {body:?}"
        );

        // All three state tokens must appear.
        assert!(
            body.contains("s-1"),
            "ChatContact s-1 must appear, body: {body:?}"
        );
        assert!(body.contains("s-2"), "Chat s-2 must appear, body: {body:?}");
        assert!(
            body.contains("s-42"),
            "Message s-42 must appear, body: {body:?}"
        );

        // The event id must be the highest version (s-42), not s-1 or s-2.
        // SSE id field is on its own line: "id: s-42"
        assert!(
            body.lines().any(|l| l == "id: s-42"),
            "event id must be highest state version s-42, body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // ping_event_is_first_on_stream
    // Oracle: RFC 8620 §7.3 — when ?ping=30, the first SSE event the client
    //         receives must be a "ping" event with data {"interval":30}.
    //         We use closeafter=state; the stream delivers the ping first,
    //         then waits for one live state event to close.  A background
    //         task sends a Message state event to let the stream terminate.
    //         Independent oracle: interval value 30 was hardcoded in the URL.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn ping_event_is_first_on_stream() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        // Send a live state event after the handler subscribes so the stream
        // can terminate (closeafter=state waits for one live state event when
        // there are no state replays).
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Message", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?ping=30&closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // First event must be a ping event.
        let first_event_line = body
            .lines()
            .find(|l| l.starts_with("event:"))
            .expect("must have at least one event line");
        assert_eq!(
            first_event_line, "event: ping",
            "first event must be 'ping', got body: {body:?}"
        );

        // Ping data must be {"interval":30} — hardcoded oracle value.
        let data_line = body
            .lines()
            .find(|l| l.starts_with("data:"))
            .expect("must have a data line");
        let json_str = data_line.strip_prefix("data:").unwrap_or(data_line).trim();
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).expect("ping data must be valid JSON");
        assert_eq!(
            parsed["interval"].as_u64(),
            Some(30),
            "ping data must carry interval=30, got: {parsed}"
        );
    }

    // -----------------------------------------------------------------------
    // ping_zero_treated_as_none
    // Oracle: ?ping=0 must be treated as absent — no ping event must appear.
    //         We use closeafter=state and send a live state event to close
    //         the stream.  The body must contain "event: state" but not
    //         "event: ping".
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn ping_zero_treated_as_none() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Message", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?ping=0&closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        assert!(
            !body.contains("event: ping"),
            "ping=0 must not emit a ping event, got body: {body:?}"
        );
        assert!(
            body.contains("event: state"),
            "state event must still be delivered, got body: {body:?}"
        );
    }

    // -----------------------------------------------------------------------
    // ping_over_300_clamped
    // Oracle: ?ping=999 must be clamped to 300.  The ping event data must
    //         show {"interval":300}, not {"interval":999}.
    //         Independent oracle: 300 is the PING_MAX_SECS constant; 999 is
    //         the value sent in the URL — neither is derived from the code
    //         path under test.  We use closeafter=state; a live state event
    //         is sent to allow the stream to terminate after the ping.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn ping_over_300_clamped() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        // Send a live state event after the handler subscribes so the stream
        // can terminate (closeafter=state waits for one live state event when
        // there are no state replays).
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = tx.send(StateChange::new("Message", "s-1".to_string()));
        });

        let req = Request::builder()
            .uri("/jmap/events?ping=999&closeafter=state")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = std::str::from_utf8(&body_bytes).unwrap();

        // Verify the first event is a ping event, then check its data.
        let lines: Vec<&str> = body.lines().collect();
        let event_line = lines
            .iter()
            .find(|l| l.starts_with("event:"))
            .expect("must have an event: line");
        assert_eq!(
            event_line.trim(),
            "event: ping",
            "first event must be a ping event, got: {event_line}"
        );
        let data_line = lines
            .iter()
            .find(|l| l.starts_with("data:"))
            .expect("must have a data line");
        let json_str = data_line.strip_prefix("data:").unwrap_or(data_line).trim();
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).expect("ping data must be valid JSON");
        assert_eq!(
            parsed["interval"].as_u64(),
            Some(300),
            "ping=999 must be clamped to 300, got: {parsed}"
        );
    }

    // -----------------------------------------------------------------------
    // events_coalescing_task_exits_on_disconnect_before_any_broadcast
    // Oracle: when live_rx is dropped (client disconnect), live_tx.closed()
    //         becomes ready immediately.  On the first yield_now() the tokio
    //         scheduler runs the coalescing task; the select! live_tx.closed()
    //         arm fires → task breaks.  The Chat broadcast sent afterwards
    //         arrives at an empty channel (receiver_count = 0 already) and is
    //         discarded.
    //         We observe task exit by watching the broadcast receiver_count()
    //         drop from 1 (task running) to 0 (task exited).
    //
    // Note: this test exercises the same select! closed() arm as
    // events_coalescing_task_exits_via_select_closed_arm. The Chat broadcast
    // sent after drop(resp) arrives at an empty channel (task already exited)
    // and is discarded. It is kept as a belt-and-suspenders regression for the
    // is_closed() empty-batch path in case future scheduler changes alter timing.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_coalescing_task_exits_on_disconnect_before_any_broadcast() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        assert_eq!(tx.receiver_count(), 0, "no receivers before subscription");

        // Subscribe with a type filter that will never match our broadcasts.
        let req = Request::builder()
            .uri("/jmap/events?types=ChatContact")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Wait for the coalescing task to subscribe — retry up to 10 yields.
        let subscribed = {
            let mut found = false;
            for _ in 0..10 {
                tokio::task::yield_now().await;
                if tx.receiver_count() == 1 {
                    found = true;
                    break;
                }
            }
            found
        };
        assert!(
            subscribed,
            "coalescing task must subscribe within 10 yields"
        );

        // Drop the response — this drops the response body, which drops live_rx,
        // which makes live_tx.closed() resolve in the coalescing task.
        drop(resp);

        // Two yields to let any pending futures make progress.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // The coalescing task is blocked at rx.recv() — send a Chat broadcast to
        // wake it up.  The ChatContact filter drops this event, the batch is empty,
        // and is_closed() in the empty-batch path detects the dropped receiver and
        // breaks.
        let _ = tx.send(StateChange::new("Chat", "s-1".to_string()));

        // Yield to let the task process the recv(), see the filtered-empty batch,
        // call is_closed(), and break.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            tx.receiver_count(),
            0,
            "coalescing task must have exited after client disconnect"
        );
    }

    // -----------------------------------------------------------------------
    // events_coalescing_task_exits_via_select_closed_arm
    // Oracle: when the client disconnects and NO broadcasts are ever sent,
    //         the coalescing task must exit via the live_tx.closed() arm in
    //         the select! at the top of the loop, not via is_closed() in the
    //         empty-batch path (which requires a broadcast to wake the task).
    //
    //         Without the select! fix, the task would block at rx.recv()
    //         indefinitely because is_closed() is only checked after a
    //         broadcast arrives — and no broadcast ever arrives in this test.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn events_coalescing_task_exits_via_select_closed_arm() {
        let state = make_state(
            MockTransport(Some(make_identity("uid-owner", "owner@example.com"))),
            "uid-owner",
        );
        let tx = state.events_tx.clone();
        let app = make_app(state);

        let req = Request::builder()
            .uri("/jmap/events?types=ChatContact")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Wait for the coalescing task to subscribe — retry up to 10 yields.
        let subscribed = {
            let mut found = false;
            for _ in 0..10 {
                tokio::task::yield_now().await;
                if tx.receiver_count() == 1 {
                    found = true;
                    break;
                }
            }
            found
        };
        assert!(
            subscribed,
            "coalescing task must subscribe within 10 yields"
        );

        // Simulate client disconnect: drop the response body.
        // This drops live_rx, making live_tx.closed() resolve.
        drop(resp);

        // Yield several times to let the select! closed() arm fire.
        // No broadcast is sent — the only way the task can exit is via select!.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        assert_eq!(
            tx.receiver_count(),
            0,
            "coalescing task must exit via select! closed() arm when no broadcasts arrive"
        );
    }
}
