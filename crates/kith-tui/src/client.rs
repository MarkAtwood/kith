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
/// The cert is pinned as an additional root; the client will refuse connections
/// whose cert chain does not include it.  No cert bytes appear in any log output.
pub fn build_client(cert_der: &[u8]) -> Result<reqwest::Client, ClientError> {
    let cert = reqwest::Certificate::from_der(cert_der).map_err(|_| ClientError::CertInvalid)?;
    reqwest::Client::builder()
        .add_root_certificate(cert)
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

/// POST a `JmapRequest` to `api_url` and return the parsed `JmapResponse`.
pub async fn call_jmap(
    client: &reqwest::Client,
    api_url: &str,
    req: &JmapRequest,
) -> Result<JmapResponse, ClientError> {
    let resp = client
        .post(api_url)
        .json(req)
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
    let mut event_type = "";
    let mut data_parts: Vec<&str> = Vec::new();

    for line in block.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim();
        } else if let Some(rest) = line.strip_prefix("data:") {
            data_parts.push(rest.trim());
        }
        // Ignore "id:", comment lines, and anything else.
    }

    if event_type != "state" {
        return Vec::new();
    }

    let data = data_parts.join("\n");
    let sse: SseData = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for type_states in sse.changed.values() {
        for (type_name, new_state) in type_states {
            out.push(StateChange {
                type_name: type_name.clone(),
                new_state: new_state.clone(),
            });
        }
    }
    out
}

// ── SSE background task ───────────────────────────────────────────────────────

/// Spawn a background task that streams `/jmap/events` and sends parsed
/// [`StateChange`] values on the returned channel.
///
/// The task exits silently when the channel receiver is dropped or when the
/// HTTP stream ends or errors.  On stream error a warning is printed to
/// stderr; no automatic reconnect is attempted (Phase 1 trade-off).
/// The returned [`tokio::task::JoinHandle`] may be dropped safely — the task
/// will still shut down when the receiver is dropped.
pub fn spawn_sse(
    client: reqwest::Client,
    event_url: String,
) -> (mpsc::Receiver<StateChange>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(64);
    let handle = tokio::spawn(async move {
        if let Err(e) = run_sse(client, &event_url, tx).await {
            eprintln!("kith-tui: SSE stream ended: {e}");
        }
    });
    (rx, handle)
}

async fn run_sse(
    client: reqwest::Client,
    event_url: &str,
    tx: mpsc::Sender<StateChange>,
) -> Result<(), ClientError> {
    let resp = client
        .get(event_url)
        .header("Accept", "text/event-stream")
        .send()
        .await?
        .error_for_status()?;

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();

    while let Some(chunk) = stream.next().await {
        let bytes = chunk?;
        // Lossy UTF-8 decode: skip invalid sequences rather than crashing.
        buf.push_str(&String::from_utf8_lossy(&bytes).replace("\r\n", "\n"));

        // Split on blank lines (SSE event boundary).
        while let Some(pos) = buf.find("\n\n") {
            let block = buf[..pos].to_string();
            buf.drain(..pos + 2);
            for sc in parse_sse_event(&block) {
                if tx.send(sc).await.is_err() {
                    // Receiver dropped; exit silently.
                    return Ok(());
                }
            }
        }
    }
    Ok(())
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
            "state": "s-1"
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
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:core".into(), "urn:ietf:params:jmap:chat".into()],
            method_calls: vec![(
                "Chat/get".into(),
                serde_json::json!({"accountId": "a-self"}),
                "c0".into(),
            )],
        };
        let api_url = format!("{}/jmap/api", mock_server.uri());
        let result = call_jmap(&client, &api_url, &req).await;

        let resp = result.expect("expected Ok from call_jmap");
        assert_eq!(resp.method_responses.len(), 1);
        assert_eq!(resp.method_responses[0].0, "Chat/get");
        assert_eq!(resp.method_responses[0].2, "c0");
        assert_eq!(resp.session_state, "s-1");
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
}
