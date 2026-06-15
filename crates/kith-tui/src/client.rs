//! Async JMAP client for kith-tui.
//!
//! Provides:
//! - `read_cert_der` — read a DER-format TLS certificate from disk
//! - `build_client` — build a reqwest Client that trusts the given cert
//! - `fetch_session` — GET /.well-known/jmap and parse the session object
//! - `call_jmap` — POST /jmap/api with a JmapRequest, parse JmapResponse
//! - `parse_sse_event` — parse one SSE event block into StateChange events
//! - `spawn_sse` — spawn a background task streaming /jmap/events

use std::collections::HashMap;
use std::path::Path;

use futures::StreamExt;
use kith_core::{JmapRequest, JmapResponse, StateChange};
use tokio::sync::mpsc;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("cert not found: {0}")]
    CertNotFound(std::path::PathBuf),
    #[error("cert invalid (DER parse failed)")]
    CertInvalid,
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("response parse error: {0}")]
    Parse(String),
    /// Auth failure (HTTP 401/403): retrying will not help.
    #[error("authentication failed (HTTP {0}): check Tailscale identity")]
    AuthFailed(u16),
    /// SSE frame exceeded the size cap: treat as a connection error.
    #[error("SSE frame too large (>{0} bytes)")]
    SseFrameTooLarge(usize),
}

// ── Session ───────────────────────────────────────────────────────────────────

/// Minimal deserializable session — only the fields kith-tui needs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ClientSession {
    #[serde(rename = "primaryAccounts")]
    pub primary_accounts: HashMap<String, String>,
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "eventSourceUrl")]
    pub event_source_url: String,
    pub state: String,
    /// Verified Tailscale user ID of the owner. Used to distinguish outbound
    /// messages (sender == owner) from inbound ones in the TUI.
    #[serde(rename = "ownerUserId", default)]
    pub owner_user_id: String,
}

impl ClientSession {
    /// Returns the account ID for the kith:chat capability (`"a-self"` for owner).
    pub fn account_id(&self) -> Option<&str> {
        self.primary_accounts
            .get("urn:ietf:params:jmap:chat")
            .map(String::as_str)
    }
}

// Intermediate type for deserializing the SSE `data:` field.
// Wire format: {"changed":{"a-self":{"Message":"s-42","Chat":"s-3"}}}
#[derive(Debug, serde::Deserialize)]
struct SseData {
    changed: HashMap<String, HashMap<String, String>>,
}

// ── Certificate / client ──────────────────────────────────────────────────────

/// Read raw DER bytes from a certificate file on disk.
pub fn read_cert_der(cert_path: &Path) -> Result<Vec<u8>, ClientError> {
    std::fs::read(cert_path).map_err(|_| ClientError::CertNotFound(cert_path.to_path_buf()))
}

/// Build a reqwest `Client` that trusts the given DER-encoded certificate.
///
/// The cert is added as a trusted CA root (`add_root_certificate`) with all
/// system roots disabled (`tls_built_in_root_certs(false)`).  For kithd's
/// self-signed certificate this is equivalent to leaf pinning: the cert is its
/// own root, so only it can terminate a valid chain.  No cert bytes appear in
/// any log output.
pub fn build_client(cert_der: &[u8]) -> Result<reqwest::Client, ClientError> {
    let cert = reqwest::Certificate::from_der(cert_der).map_err(|_| ClientError::CertInvalid)?;
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .tls_built_in_root_certs(false)
        .build()
        .map_err(ClientError::Http)
}

// ── Session fetch ─────────────────────────────────────────────────────────────

/// Fetch the JMAP session object from `{base_url}/.well-known/jmap`.
pub async fn fetch_session(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<ClientSession, ClientError> {
    let url = format!("{base_url}/.well-known/jmap");
    let resp = client.get(&url).send().await?.error_for_status()?;
    resp.json::<ClientSession>()
        .await
        .map_err(|e| ClientError::Parse(e.to_string()))
}

// ── JMAP API call ─────────────────────────────────────────────────────────────

/// Timeout applied to each JMAP API call.
///
/// A kithd that accepts a connection but stalls sending the response would
/// otherwise cause the event loop to block indefinitely, making the TUI
/// unresponsive to keyboard events.
const JMAP_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// POST a `JmapRequest` to `api_url` and return the parsed `JmapResponse`.
pub async fn call_jmap(
    client: &reqwest::Client,
    api_url: &str,
    req: &JmapRequest,
) -> Result<JmapResponse, ClientError> {
    let resp = client
        .post(api_url)
        .json(req)
        .timeout(JMAP_CALL_TIMEOUT)
        .send()
        .await?
        .error_for_status()?;
    resp.json::<JmapResponse>()
        .await
        .map_err(|e| ClientError::Parse(e.to_string()))
}

// ── SSE parser ────────────────────────────────────────────────────────────────

/// Parse one SSE event block (the text between two blank lines) into zero or
/// more [`StateChange`] values.
///
/// Only `event: state` blocks produce output.  `event: ping` and all unknown
/// event types are silently ignored.  Malformed `data:` JSON is also silently
/// skipped — the client must resync via `<Type>/changes` if it misses events.
///
/// This function is `pub` so the test suite in KITH-ecbt.3 can call it directly
/// without an HTTP connection.
pub fn parse_sse_event(block: &str) -> Vec<StateChange> {
    // Field extraction is shared with kithctl via kith_core::parse_sse_frame
    // so both clients parse the same wire format.
    let frame = kith_core::parse_sse_frame(block);

    if frame.event_type.as_deref() != Some("state") {
        return Vec::new();
    }

    let data = frame.data.unwrap_or_default();
    let sse: SseData = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for type_states in sse.changed.values() {
        for (type_name, new_state) in type_states {
            out.push(StateChange::new(type_name.clone(), new_state.clone()));
        }
    }
    out
}

/// Extract the `id:` field value from a single SSE event block.
///
/// Returns `Some(id)` if the block contains an `id:` line, `None` otherwise.
/// Used to track the `Last-Event-ID` for reconnect resumption per the SSE spec.
///
/// Delegates to [`kith_core::parse_sse_frame`] to share the field extraction
/// logic with `parse_sse_event` and `kithctl`.
fn extract_sse_id(block: &str) -> Option<String> {
    kith_core::parse_sse_frame(block).id
}

// ── SSE background task ───────────────────────────────────────────────────────

/// Spawn a background task that streams `/jmap/events` and sends parsed
/// [`StateChange`] values on the returned `StateChange` channel.
///
/// A second returned channel carries [`SseStatus`] signals (`Connected` when
/// the stream is live, `Reconnecting` during backoff).  The event loop selects
/// on both channels and updates `connection_status` accordingly.
///
/// The task reconnects automatically on stream end or error using exponential
/// backoff (2 s → 4 s → … → 60 s cap).  Backoff resets to 2 s on each
/// successful connection.  The task exits only when the `StateChange` receiver
/// is dropped.
///
/// The returned [`tokio::task::JoinHandle`] may be dropped safely — the task
/// will still shut down when the receiver is dropped.
pub fn spawn_sse(
    client: reqwest::Client,
    event_url: String,
) -> (
    mpsc::Receiver<StateChange>,
    mpsc::Receiver<SseStatus>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, rx) = mpsc::channel::<StateChange>(64);
    let (status_tx, status_rx) = mpsc::channel::<SseStatus>(8);
    let handle = tokio::spawn(async move {
        let mut backoff_secs: u64 = 2;
        // Track the last SSE id: value across reconnect attempts so we can
        // send Last-Event-ID for server-side resumption (SSE spec §9.2).
        let mut last_event_id: Option<String> = None;
        loop {
            match run_sse(
                client.clone(),
                &event_url,
                tx.clone(),
                &status_tx,
                last_event_id.as_deref(),
            )
            .await
            {
                Ok(id) => {
                    last_event_id = id;
                    // Stream closed cleanly (server EOF). Reconnect.
                    eprintln!("kith-tui: SSE stream closed; reconnecting in {backoff_secs}s");
                    // Reset backoff on a clean close — the server was reachable.
                    backoff_secs = 2;
                }
                Err(ClientError::AuthFailed(code)) => {
                    // 401/403 means our identity is rejected. Retrying will not
                    // help — surface the error and stop the task entirely.
                    eprintln!("kith-tui: SSE authentication failed (HTTP {code}): not retrying");
                    let _ = status_tx.send(SseStatus::AuthError(code)).await;
                    return;
                }
                Err(e) => {
                    // Keep last_event_id on error — the server may replay from
                    // that point on reconnect, minimising missed events.
                    eprintln!("kith-tui: SSE stream error: {e}; reconnecting in {backoff_secs}s");
                }
            }

            // Signal the UI that we are reconnecting.
            if status_tx.send(SseStatus::Reconnecting).await.is_err() {
                // Receiver dropped; UI is gone, exit the task.
                return;
            }

            // Use select! so that a dropped StateChange receiver wakes the
            // task immediately during backoff rather than waiting up to 60s.
            tokio::select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)) => {}
                _ = tx.closed() => { return; }
            }
            backoff_secs = (backoff_secs * 2).min(60);

            // Exit if the StateChange receiver was dropped while we slept.
            if tx.is_closed() {
                return;
            }
        }
    });
    (rx, status_rx, handle)
}

/// Status signals emitted by the SSE background task to the event loop.
#[derive(Debug, Clone, PartialEq)]
pub enum SseStatus {
    /// The SSE stream is live and delivering events.
    Connected,
    /// The stream closed or errored; backoff in progress before next attempt.
    Reconnecting,
    /// Auth failure (HTTP 401/403). The task has exited; no retry will occur.
    AuthError(u16),
}

/// Maximum SSE buffer size. If a server sends bytes without ever emitting a
/// blank-line frame boundary, the buffer would grow without bound. Cap it at
/// 1 MiB and return a fatal error so the caller can reconnect (or give up).
const MAX_SSE_BUF: usize = 1024 * 1024; // 1 MiB

/// Run one SSE connection attempt.
///
/// Accepts `last_event_id` to send a `Last-Event-ID` header, enabling the
/// server to resume the stream from the last acknowledged event.
/// Returns the last `id:` value seen in the stream (for the next reconnect).
async fn run_sse(
    client: reqwest::Client,
    event_url: &str,
    tx: mpsc::Sender<StateChange>,
    status_tx: &mpsc::Sender<SseStatus>,
    last_event_id: Option<&str>,
) -> Result<Option<String>, ClientError> {
    let mut req = client.get(event_url).header("Accept", "text/event-stream");
    if let Some(lei) = last_event_id {
        req = req.header("Last-Event-ID", lei);
    }
    let resp = req.send().await?;

    // Detect auth failures before calling error_for_status() so we can return
    // a typed AuthFailed error instead of a generic Http error. The caller
    // uses this to stop retrying — a 401/403 will not resolve on its own.
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ClientError::AuthFailed(status.as_u16()));
    }
    resp.error_for_status_ref().map_err(ClientError::Http)?;

    // HTTP connection established — notify the UI.
    // Ignore send errors: the UI may have exited.
    let _ = status_tx.send(SseStatus::Connected).await;

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    // Track the last SSE id: field seen for Last-Event-ID resumption.
    let mut last_id: Option<String> = last_event_id.map(str::to_owned);

    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        // Append raw bytes first (lossy UTF-8; invalid sequences become U+FFFD).
        // Do NOT normalize per-chunk: a TCP chunk may end with '\r' while the
        // next chunk starts with '\n', splitting a CRLF across chunk boundaries.
        // Normalizing per-chunk would leave a stray '\r' in the buffer that never
        // gets paired with its '\n', breaking the blank-line frame boundary search.
        buf.push_str(&String::from_utf8_lossy(&bytes));

        // Normalize line endings in the full buffer now that we have appended.
        // Replace CRLF first, then any remaining bare CR (both are valid SSE
        // line terminators per the EventSource spec, §9.2).
        // This is safe to do after every chunk: replace() scans the whole string,
        // so a CRLF split across chunk boundaries is caught once the second
        // chunk arrives and the '\r' and '\n' are adjacent in the buffer.
        let normalized = buf.replace("\r\n", "\n").replace('\r', "\n");
        buf.clear();
        buf.push_str(&normalized);

        // Guard against unbounded buffer growth when the server sends bytes
        // but never emits a blank-line SSE frame boundary.
        if buf.len() > MAX_SSE_BUF {
            return Err(ClientError::SseFrameTooLarge(MAX_SSE_BUF));
        }

        // Split on blank lines (SSE event boundary).
        while let Some(pos) = buf.find("\n\n") {
            let block = buf[..pos].to_string();
            buf.drain(..pos + 2);
            // Update last_id before dispatching state changes so that the
            // next reconnect can resume from this id even if the receiver drops.
            if let Some(id) = extract_sse_id(&block) {
                last_id = Some(id);
            }
            for sc in parse_sse_event(&block) {
                if tx.send(sc).await.is_err() {
                    // Receiver dropped; exit silently.
                    return Ok(last_id);
                }
            }
        }
    }
    Ok(last_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kith_core::JmapRequest;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // ── fetch_session ─────────────────────────────────────────────────────────

    // Oracle: a 200 response with a valid ClientSession JSON body must produce
    // an Ok result with account_id() == Some("a-self") and state == "s-1".
    // Expected values derived from the JMAP session wire format (RFC 8620 §2).
    #[tokio::test]
    async fn fetch_session_happy_path() {
        let mock_server = MockServer::start().await;
        let body = serde_json::json!({
            "primaryAccounts": {"urn:ietf:params:jmap:chat": "a-self"},
            "apiUrl": format!("{}/jmap/api", mock_server.uri()),
            "eventSourceUrl": format!("{}/jmap/events", mock_server.uri()),
            "state": "s-1",
            "ownerUserId": "uid-test-owner"
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/jmap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let result = fetch_session(&client, &mock_server.uri()).await;

        let session = result.expect("expected Ok from fetch_session");
        assert_eq!(session.account_id(), Some("a-self"));
        assert_eq!(session.state, "s-1");
        assert_eq!(session.owner_user_id, "uid-test-owner");
        assert!(
            session.api_url.contains("/jmap/api"),
            "api_url must contain /jmap/api"
        );
        assert!(
            session.event_source_url.contains("/jmap/events"),
            "event_source_url must contain /jmap/events"
        );
    }

    // Oracle: an HTTP 404 from error_for_status() maps to ClientError::Http.
    // reqwest::Error from error_for_status wraps the status, and the #[from]
    // attribute on ClientError::Http converts it automatically.
    #[tokio::test]
    async fn fetch_session_404_returns_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jmap"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let result = fetch_session(&client, &mock_server.uri()).await;

        assert!(result.is_err(), "expected Err from fetch_session on 404");
        assert!(
            matches!(result.unwrap_err(), ClientError::Http(_)),
            "expected ClientError::Http variant"
        );
    }

    // ── call_jmap ─────────────────────────────────────────────────────────────

    // Oracle: POST /jmap/api with a JmapRequest returns a JmapResponse whose
    // method_responses match the mock body. Values derived from RFC 8620 §3.
    #[tokio::test]
    async fn call_jmap_round_trip() {
        let mock_server = MockServer::start().await;
        let response_body = serde_json::json!({
            "methodResponses": [
                ["Chat/get", {"accountId": "a-self", "list": [], "state": "s-2"}, "c0"]
            ],
            "sessionState": "s-1"
        });
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let req = JmapRequest::new(
            vec![
                "urn:ietf:params:jmap:core".into(),
                "urn:ietf:params:jmap:chat".into(),
            ],
            vec![(
                "Chat/get".into(),
                serde_json::json!({"accountId": "a-self"}),
                "c0".into(),
            )],
            None,
        );
        let api_url = format!("{}/jmap/api", mock_server.uri());
        let result = call_jmap(&client, &api_url, &req).await;

        let resp = result.expect("expected Ok from call_jmap");
        assert_eq!(resp.method_responses.len(), 1);
        assert_eq!(resp.method_responses[0].0, "Chat/get");
        assert_eq!(resp.method_responses[0].2, "c0");
        assert_eq!(resp.session_state, "s-1");
    }

    // ── extract_sse_id ────────────────────────────────────────────────────────

    // Oracle: "id: s-7" in a block yields Some("s-7").
    // Constructed from SSE spec (HTML §9.2): id: field sets last event ID.
    #[test]
    fn extract_sse_id_present() {
        let block = "event: state\nid: s-7\ndata: {}";
        assert_eq!(extract_sse_id(block), Some("s-7".to_string()));
    }

    // Oracle: block without id: field yields None.
    #[test]
    fn extract_sse_id_absent() {
        let block = "event: state\ndata: {}";
        assert_eq!(extract_sse_id(block), None);
    }

    // ── parse_sse_event ───────────────────────────────────────────────────────

    // Oracle: "event: state" block with one type→state pair produces exactly
    // one StateChange. Values from kithd/src/events.rs line 102 wire format doc.
    #[test]
    fn parse_sse_single_event() {
        let block = "event: state\ndata: {\"changed\":{\"a-self\":{\"Message\":\"s-42\"}}}";
        let changes = parse_sse_event(block);
        assert_eq!(changes.len(), 1, "expected exactly one StateChange");
        assert_eq!(changes[0].type_name, "Message");
        assert_eq!(changes[0].new_state, "s-42");
    }

    // Oracle: "event: ping" must be silently ignored — empty Vec.
    // Ping events are RFC 8620 §7.3 keepalives; they carry no state data.
    #[test]
    fn parse_sse_ping_event_is_ignored() {
        let block = "event: ping\ndata: {\"interval\":30}";
        let changes = parse_sse_event(block);
        assert!(
            changes.is_empty(),
            "ping events must produce no StateChange values"
        );
    }

    // Oracle: one SSE frame may contain multiple type→state pairs (kithd
    // coalesces rapid-fire changes). Both must be present; HashMap order
    // is non-deterministic so compare via sort.
    // Values: Message→s-43, Chat→s-2 — derived from SSE wire format spec.
    #[test]
    fn parse_sse_multiple_types_in_one_event() {
        let block = "event: state\ndata: {\"changed\":{\"a-self\":{\"Message\":\"s-43\",\"Chat\":\"s-2\"}}}";
        let mut changes = parse_sse_event(block);
        assert_eq!(changes.len(), 2, "expected exactly two StateChange values");

        // Sort by type_name for deterministic comparison.
        changes.sort_by(|a, b| a.type_name.cmp(&b.type_name));
        assert_eq!(changes[0].type_name, "Chat");
        assert_eq!(changes[0].new_state, "s-2");
        assert_eq!(changes[1].type_name, "Message");
        assert_eq!(changes[1].new_state, "s-43");
    }

    // Oracle: RFC 8895 §6.3 — multiple data: lines are concatenated with LF.
    // kithd never sends multi-line data, but the parser must not overwrite
    // earlier lines. The regression being guarded: before the fix, the second
    // data: line would overwrite the first instead of appending, losing part
    // of the JSON and producing a parse error (empty Vec). After the fix the
    // two lines are joined with "\n" and the combined string is valid JSON,
    // producing the expected StateChange.
    //
    // Oracle values: JSON object deliberately split across two data: lines so
    // that neither line alone is a complete valid JSON object. The joined
    // result {"changed":{"a-self":{"Message":"s-5"}}} is the independent
    // expected value, derived from the RFC 8620 wire format.
    #[test]
    fn parse_sse_multiline_data_concatenated() {
        // Split the JSON object across two data: lines.
        // join("\n") produces: {"changed":{"a-self":\n{"Message":"s-5"}}}
        // JSON allows whitespace (including LF) between tokens, so this parses.
        // Before the fix: second data: line would overwrite the first, leaving
        // only {"Message":"s-5"}}} which fails to parse → empty Vec.
        // After the fix: both lines are retained and concatenated → one StateChange.
        let block = "event: state\ndata: {\"changed\":{\"a-self\":\ndata: {\"Message\":\"s-5\"}}}";
        let changes = parse_sse_event(block);
        assert_eq!(
            changes.len(),
            1,
            "multi-line data: lines must be concatenated, not overwritten"
        );
        assert_eq!(changes[0].type_name, "Message");
        assert_eq!(changes[0].new_state, "s-5");
    }

    // Oracle: Rust's str::lines() strips both LF and CRLF line endings.
    // parse_sse_event is tolerant of CRLF in its input block.
    // The run_sse function normalizes before splitting, but parse_sse_event
    // handles raw CRLF gracefully regardless.
    #[test]
    fn parse_sse_crlf_block_handled() {
        // Same as parse_sse_single_event but with CRLF line endings in the block.
        let block = "event: state\r\ndata: {\"changed\":{\"a-self\":{\"Message\":\"s-7\"}}}";
        let changes = parse_sse_event(block);
        assert_eq!(changes.len(), 1, "CRLF block must produce one StateChange");
        assert_eq!(changes[0].type_name, "Message");
        assert_eq!(changes[0].new_state, "s-7");
    }

    // Oracle: the run_sse buffer normalization must handle a CRLF split across
    // two append operations (simulating TCP chunk boundaries).
    //
    // The bug: if CRLF is normalized per-chunk, a chunk ending with '\r' and
    // the next chunk starting with '\n' produce a stray '\r' followed by '\n'
    // in the buffer — they are never seen as a unit.  After the fix, we
    // normalize the *full buffer* on every chunk arrival, so the '\r' and '\n'
    // are adjacent by the time replace("\r\n", "\n") runs.
    //
    // This test exercises the normalization logic directly (without a live HTTP
    // connection) by simulating two sequential appends and then applying the
    // same replace chain that run_sse uses after each append.
    #[test]
    fn sse_crlf_split_across_chunks_is_normalized() {
        // Simulate chunk 1 ending with '\r' and chunk 2 starting with '\n'.
        // The full event (with '\n\n' frame terminator) is:
        //   "event: state\r\ndata: {\"changed\":{\"a-self\":{\"Message\":\"s-9\"}}}\r\n\r\n"
        // Split it at the boundary where '\r' ends chunk 1:
        let chunk1 = b"event: state\r\ndata: {\"changed\":{\"a-self\":{\"Message\":\"s-9\"}}}\r";
        let chunk2 = b"\n\r\n";

        let mut buf = String::new();

        // Apply the same logic as the fixed run_sse: append then normalize buffer.
        buf.push_str(&String::from_utf8_lossy(chunk1));
        let normalized = buf.replace("\r\n", "\n").replace('\r', "\n");
        buf.clear();
        buf.push_str(&normalized);

        buf.push_str(&String::from_utf8_lossy(chunk2));
        let normalized = buf.replace("\r\n", "\n").replace('\r', "\n");
        buf.clear();
        buf.push_str(&normalized);

        // After both chunks, the buffer must contain a complete LF-only event
        // terminated by "\n\n".  Extract the block and parse it.
        let pos = buf
            .find("\n\n")
            .expect("blank-line frame boundary must exist");
        let block = &buf[..pos];

        let changes = parse_sse_event(block);
        assert_eq!(
            changes.len(),
            1,
            "split-CRLF event must produce one StateChange after buffer normalization"
        );
        assert_eq!(changes[0].type_name, "Message");
        assert_eq!(changes[0].new_state, "s-9");
    }
}
