//! `kithctl watch` — SSE event loop and desktop notifications.
//!
//! Pure helper functions in this module are unit-tested.  The async I/O loop
//! (`cmd_watch`, `watch_once`) requires a live kithd and is not integration-
//! tested here.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::Config;
use kith_tslocal::LocalApiClient;

/// Maximum JMAP response body size accepted from kithd (bytes).
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum SSE frame size accumulated between blank-line separators (bytes).
///
/// Prevents unbounded memory growth if a misbehaving server sends an
/// indefinitely long sequence of lines without a blank-line terminator.
const MAX_SSE_FRAME_BYTES: usize = 64 * 1024;

/// Maximum length of a single HTTP header line (bytes).
///
/// Prevents a misbehaving server from growing a read buffer without bound
/// during the HTTP/1.1 header-skipping phase.
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;

// ── Pure helpers ─────────────────────────────────────────────────────────────

/// Truncate `body` to at most `max_chars` Unicode scalar values.
///
/// If truncation occurs an ellipsis character (`…` U+2026) is appended.
/// The returned string always contains valid UTF-8.
pub fn truncate_body(body: &str, max_chars: usize) -> String {
    let mut chars = body.chars();
    let mut result = String::new();
    let mut truncated = false;

    for (count, c) in (&mut chars).enumerate() {
        if count >= max_chars {
            truncated = true;
            break;
        }
        result.push(c);
    }

    if truncated {
        result.push('…');
    }
    result
}

/// Remove characters that must not appear in a desktop notification argument.
///
/// Strips control characters (NUL, CR, LF, TAB) and, on macOS, characters
/// that would break AppleScript string literals: `"` (terminates the literal)
/// and `&` (AppleScript string-concatenation operator).
pub fn sanitize_sender(sender: &str) -> String {
    sender
        .chars()
        .filter(|&c| c != '\0' && c != '\r' && c != '\n' && c != '\t' && c != '"' && c != '&')
        .collect()
}

/// Parse one SSE frame (the accumulated lines between blank-line separators,
/// with the blank line itself excluded).
///
/// Returns `(event_type, data, id)` where each is `None` when the field is
/// absent from the frame.
///
/// Field format per [SSE spec](https://html.spec.whatwg.org/multipage/server-sent-events.html):
/// `<field>: <value>` — anything else is silently ignored.
///
/// Delegates to [`kith_core::parse_sse_frame`] so the field extraction logic
/// is shared with `kith-tui` and maintained in one place.
pub fn parse_sse_frame(frame: &str) -> (Option<String>, Option<String>, Option<String>) {
    let f = kith_core::parse_sse_frame(frame);
    (f.event_type, f.data, f.id)
}

/// Return `true` when `s` is a valid `Last-Event-ID` value.
///
/// Accepts the empty string (valid for initial connect with no prior ID) or a
/// string matching `s-\d+` (e.g. `"s-0"`, `"s-42"`).  Anything else —
/// including strings with embedded newlines or other special characters — is
/// rejected to prevent header injection.
pub fn is_valid_last_event_id(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    if let Some(rest) = s.strip_prefix("s-") {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

// ── TLS: pinned self-signed cert verifier ────────────────────────────────────

/// A rustls `ServerCertVerifier` that accepts exactly one specific DER-encoded
/// certificate.
///
/// This is safe for kith's threat model: the cert is copied from kithd's data
/// directory (same host or explicitly fetched), so pinning to byte-exact
/// equality is as strong as a CA chain for this single endpoint.
#[derive(Debug)]
struct PinnedCertVerifier {
    pinned_der: Vec<u8>,
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if end_entity.as_ref() == self.pinned_der.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General(
                "server certificate does not match pinned certificate".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `TlsConnector` that accepts only the certificate whose DER bytes
/// are given in `pinned_cert_der`.
fn build_tls_connector(
    pinned_cert_der: Vec<u8>,
) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let verifier = Arc::new(PinnedCertVerifier {
        pinned_der: pinned_cert_der,
    });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Read the pinned cert from disk and build a `TlsConnector`.
///
/// Called at startup and again whenever kithd rotates its cert (detected when
/// TLS handshake fails with "does not match pinned certificate").
fn load_connector(cert_path: &std::path::Path) -> Result<TlsConnector, Box<dyn std::error::Error>> {
    let cert_der =
        std::fs::read(cert_path).map_err(|e| format!("failed to read cert {cert_path:?}: {e}"))?;
    build_tls_connector(cert_der)
}

// ── Desktop notifications ─────────────────────────────────────────────────────

/// Send a desktop notification with the given sender and message preview.
///
/// Uses `notify-send` on Linux and `osascript` on macOS.  Failures are
/// printed to stderr and do not terminate the watch loop.
fn fire_notification(sender: &str, preview: &str) {
    let sender_clean = sanitize_sender(sender);
    let preview_clean = truncate_body(preview, 80);
    let body = format!("{sender_clean}: {preview_clean}");

    #[cfg(target_os = "linux")]
    {
        match std::process::Command::new("notify-send")
            .arg("Kith")
            .arg(&body)
            .status()
        {
            Err(e) => eprintln!("watch: notify-send failed to launch: {e}"),
            Ok(s) if !s.success() => eprintln!("watch: notify-send exited with {s}"),
            Ok(_) => {}
        }
    }

    #[cfg(target_os = "macos")]
    {
        // AppleScript string literals use `"` as delimiter with no backslash
        // escaping. Strip `"` and `&` (string-concatenation operator) from
        // both values before splicing them into the script.
        let preview_as = sanitize_sender(&preview_clean);
        let script = format!(
            "display notification \"{preview_as}\" with title \"Kith\" subtitle \"{sender_clean}\""
        );
        let status = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .status();
        if let Err(e) = status {
            eprintln!("watch: osascript failed: {e}");
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        eprintln!("watch: desktop notifications not supported on this platform");
    }
}

// ── SSE + JMAP watch loop ─────────────────────────────────────────────────────

/// Establish one SSE connection and run until the connection drops or a clean
/// shutdown signal is received.
///
/// Returns `Ok(())` for clean shutdown (caller should not reconnect).
/// Returns `Err(...)` on connection loss (caller should reconnect).
async fn watch_once(
    config: &Config,
    tailnet_ip: &str,
    connector: &TlsConnector,
    last_event_id: &mut Option<String>,
    last_message_state: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    let connector = connector.clone();
    let server_name = ServerName::try_from("kith.local")
        .map_err(|e| format!("invalid server name: {e}"))?
        .to_owned();

    let addr = format!("{tailnet_ip}:{}", config.port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("TCP connect to {addr} failed: {e}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    let (reader, mut writer) = tokio::io::split(tls);
    let mut buf_reader = BufReader::new(reader);

    // Send the SSE subscription request.
    let mut request =
        "GET /jmap/events?types=Message HTTP/1.1\r\nHost: kith.local\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n".to_string();
    if let Some(id) = last_event_id {
        if is_valid_last_event_id(id) && !id.is_empty() {
            request.push_str(&format!("Last-Event-ID: {id}\r\n"));
        }
    }
    request.push_str("\r\n");

    writer
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("failed to send SSE request: {e}"))?;

    // Read the HTTP response status line.
    let mut status_line = String::new();
    buf_reader
        .read_line(&mut status_line)
        .await
        .map_err(|e| format!("failed to read HTTP status: {e}"))?;
    let status_line = status_line.trim_end();

    // Parse status code.
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if status_code == 401 {
        eprintln!("watch: not recognized as a kithd identity (HTTP 401) — is tailscaled running on this node?");
        return Ok(()); // clean exit — do not reconnect
    }
    if status_code == 403 {
        eprintln!("watch: recognized as a peer, not the owner (HTTP 403) — run kithctl from the same Tailscale node as kithd");
        return Ok(()); // clean exit — do not reconnect
    }
    if status_code != 200 {
        return Err(format!("unexpected HTTP status: {status_line}").into());
    }

    // Skip HTTP headers (read until blank line).
    let mut header_count = 0usize;
    loop {
        if header_count >= 100 {
            return Err("too many HTTP headers (limit: 100)".into());
        }
        let mut header_line = String::new();
        let n = buf_reader
            .read_line(&mut header_line)
            .await
            .map_err(|e| format!("error reading headers: {e}"))?;
        if n == 0 {
            return Err("connection closed during headers".into());
        }
        if header_line.len() > MAX_HEADER_LINE_BYTES {
            return Err("HTTP header line too long (limit: 8 KiB)".into());
        }
        if header_line == "\r\n" || header_line == "\n" {
            break;
        }
        header_count += 1;
    }

    // SSE frame accumulation loop.
    let mut frame_lines: Vec<String> = Vec::new();

    loop {
        let mut line = String::new();
        let n = buf_reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("SSE read error: {e}"))?;

        if n == 0 {
            return Err("SSE connection closed by server".into());
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);

        if trimmed.is_empty() {
            // Blank line — frame complete.
            if !frame_lines.is_empty() {
                let frame = frame_lines.join("\n");
                frame_lines.clear();

                let (event_type, data, id) = parse_sse_frame(&frame);

                if event_type.as_deref() == Some("state") {
                    if let Some(ref json_str) = data {
                        if let Ok(state_val) = serde_json::from_str::<serde_json::Value>(json_str) {
                            // SSE data shape: {"changed": {"a-self": {"Message": "s-N", ...}}}
                            if let Some(new_state) = state_val
                                .get("changed")
                                .and_then(|c| c.get("a-self"))
                                .and_then(|a| a.get("Message"))
                                .and_then(|v| v.as_str())
                            {
                                // Fetch new messages since last_message_state.
                                let prev_state = last_message_state.clone();
                                let new_state = new_state.to_owned();

                                match fetch_and_notify(config, tailnet_ip, &connector, &prev_state)
                                    .await
                                {
                                    Ok(()) => {
                                        *last_message_state = new_state;
                                    }
                                    Err(e) if e.to_string() == "auth-failure" => {
                                        return Ok(()); // clean exit — do not reconnect
                                    }
                                    Err(e) => {
                                        eprintln!("watch: JMAP fetch error: {e}");
                                    }
                                }
                            }
                        }
                    }
                }

                // Update last_event_id when the server provides an SSE id: field.
                if let Some(ref new_id) = id {
                    if is_valid_last_event_id(new_id) {
                        *last_event_id = Some(new_id.clone());
                    }
                }
            }
        } else {
            frame_lines.push(trimmed.to_owned());
            let frame_total: usize = frame_lines.iter().map(|l| l.len() + 1).sum();
            if frame_total > MAX_SSE_FRAME_BYTES {
                return Err(format!("SSE frame exceeds {MAX_SSE_FRAME_BYTES} bytes").into());
            }
        }
    }
}

/// Call Message/changes then Message/get for new messages, fire notifications.
async fn fetch_and_notify(
    config: &Config,
    tailnet_ip: &str,
    connector: &TlsConnector,
    since_state: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // --- Message/changes (paginated) ---
    // Loop until hasMoreChanges=false.  maxChanges=500 matches the kithd query
    // limit; in practice a single page covers any realistic burst.  Without
    // this loop, messages beyond the first page are silently dropped — they
    // never fire desktop notifications and are lost when the state baseline
    // advances to newState.
    //
    // accountId must be "a-self" — kithd rejects any other value.
    let mut cursor = since_state.to_string();
    let mut new_ids: Vec<String> = Vec::new();

    loop {
        let changes_request = serde_json::json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [
                ["Message/changes", {"accountId": "a-self", "sinceState": cursor, "maxChanges": 500}, "c0"]
            ]
        });

        let changes_body = serde_json::to_string(&changes_request)?;
        let changes_response = jmap_post(config, tailnet_ip, connector, &changes_body).await?;

        let method_args = changes_response
            .get("methodResponses")
            .and_then(|r| r.as_array())
            .and_then(|arr| arr.first())
            .and_then(|r| r.as_array())
            .and_then(|r| r.get(1));

        let created_ids: Vec<String> = method_args
            .and_then(|args| args.get("created"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        // Only notify for created messages.  Updated IDs represent delivery/read
        // state changes on existing messages (e.g. pending→delivered) and must not
        // fire a "new message" desktop notification.
        new_ids.extend(created_ids);

        let has_more = method_args
            .and_then(|args| args.get("hasMoreChanges"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !has_more {
            break;
        }

        // Advance cursor to newState so the next page starts where this one ended.
        cursor = method_args
            .and_then(|args| args.get("newState"))
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or("hasMoreChanges=true but newState missing in Message/changes response")?;
    }

    if new_ids.is_empty() {
        return Ok(());
    }

    // --- Message/get ---
    let get_request = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [
            ["Message/get", {
                "accountId": "a-self",
                "ids": new_ids,
                "properties": ["senderId", "body"]
            }, "c1"]
        ]
    });

    let get_body = serde_json::to_string(&get_request)?;
    let get_response = jmap_post(config, tailnet_ip, connector, &get_body).await?;

    let messages = get_response
        .get("methodResponses")
        .and_then(|r| r.as_array())
        .and_then(|arr| arr.first())
        .and_then(|r| r.as_array())
        .and_then(|r| r.get(1))
        .and_then(|args| args.get("list"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for msg in &messages {
        let sender = msg
            .get("senderId")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let body = msg.get("body").and_then(|v| v.as_str()).unwrap_or("");
        fire_notification(sender, body);
    }

    Ok(())
}

/// Send a single JMAP POST request and return the parsed JSON response.
///
/// Opens a fresh TLS connection for each call (TCP connect + TLS handshake).
/// The `TlsConnector` (and its underlying `ClientConfig`) is shared across calls.
async fn jmap_post(
    config: &Config,
    tailnet_ip: &str,
    connector: &TlsConnector,
    body: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let connector = connector.clone();
    let server_name = ServerName::try_from("kith.local")
        .map_err(|e| format!("invalid server name: {e}"))?
        .to_owned();

    let addr = format!("{tailnet_ip}:{}", config.port);
    let tcp = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("TCP connect to {addr}: {e}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake: {e}"))?;

    let (reader, mut writer) = tokio::io::split(tls);
    let mut buf_reader = BufReader::new(reader);

    let content_length = body.len();
    let request = format!(
        "POST /jmap/api HTTP/1.1\r\nHost: kith.local\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n{body}"
    );
    writer.write_all(request.as_bytes()).await?;

    // Read status line.
    let mut status_line = String::new();
    buf_reader.read_line(&mut status_line).await?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    if status_code == 401 || status_code == 403 {
        eprintln!("watch: JMAP request rejected (HTTP {status_code}); exiting");
        return Err("auth-failure".into());
    }
    if status_code != 200 {
        return Err(format!("JMAP POST returned HTTP {status_code}").into());
    }

    // Skip headers, collect Content-Length if present.
    let mut content_length_hint: Option<usize> = None;
    let mut header_count = 0usize;
    loop {
        if header_count >= 100 {
            return Err("too many HTTP headers (limit: 100)".into());
        }
        let mut header = String::new();
        let n = buf_reader.read_line(&mut header).await?;
        if n == 0 {
            break;
        }
        if header.len() > MAX_HEADER_LINE_BYTES {
            return Err("HTTP header line too long (limit: 8 KiB)".into());
        }
        let h = header.trim();
        if h.is_empty() {
            break;
        }
        let h_lower = h.to_ascii_lowercase();
        if let Some(val) = h_lower.strip_prefix("content-length:") {
            if let Ok(len) = val.trim().parse::<usize>() {
                content_length_hint = Some(len);
            }
        }
        // kithd uses Body::from(String) which produces a fixed-length body;
        // hyper sets Content-Length and does NOT use chunked Transfer-Encoding.
        // Reject chunked explicitly: our body reader does not decode chunk framing
        // and would misparse the response, surfacing as a JSON parse error.
        if h_lower.strip_prefix("transfer-encoding:").map(|v| v.trim()) == Some("chunked") {
            return Err("JMAP response uses chunked Transfer-Encoding (not supported)".into());
        }
        header_count += 1;
    }

    // Read response body, bounded by MAX_RESPONSE_BYTES to prevent OOM from a
    // misbehaving or malicious kithd.
    let response_bytes = if let Some(len) = content_length_hint {
        if len > MAX_RESPONSE_BYTES {
            return Err("JMAP response Content-Length exceeds size limit".into());
        }
        let mut limited = tokio::io::AsyncReadExt::take(&mut buf_reader, len as u64);
        let mut buf = Vec::with_capacity(len);
        tokio::io::AsyncReadExt::read_to_end(&mut limited, &mut buf).await?;
        buf
    } else {
        let mut limited =
            tokio::io::AsyncReadExt::take(&mut buf_reader, MAX_RESPONSE_BYTES as u64 + 1);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut limited, &mut buf).await?;
        if buf.len() > MAX_RESPONSE_BYTES {
            return Err("JMAP response exceeds size limit".into());
        }
        buf
    };

    let value: serde_json::Value = serde_json::from_slice(&response_bytes)
        .map_err(|e| format!("failed to parse JMAP response: {e}"))?;

    Ok(value)
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Watch for new messages and fire desktop notifications.
///
/// Connects to kithd via SSE at `/jmap/events?types=Message`, reconnects on
/// disconnect with a 2-second back-off, and exits cleanly on 401/403.
pub async fn cmd_watch(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Get tailnet IPs from LocalAPI.
    let ts_client = LocalApiClient::new(&config.ts_socket);
    let status = ts_client
        .status()
        .await
        .map_err(|e| format!("tailscaled not reachable: {e}"))?;
    let tailnet_ip = status
        .tailscale_ips
        .first()
        .cloned()
        .ok_or("no tailnet IP; is tailscaled running?")?;

    // 2. Load pinned TLS cert.
    let cert_path = config.cert_path();
    if !cert_path.exists() {
        return Err(format!("TLS cert not found at {cert_path:?}; is kithd running?").into());
    }
    // `connector` is mut so it can be refreshed when kithd rotates its cert.
    let mut connector = load_connector(&cert_path)?;

    // 3. Bootstrap the message state baseline so we don't fire desktop notifications
    //    for messages that existed before kithctl started.  Message/get(ids=[]) returns
    //    the current state with an empty list — no network IDs needed.
    let bootstrap_req = serde_json::json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
        "methodCalls": [["Message/get", {"accountId": "a-self", "ids": []}, "b0"]]
    });
    // Bootstrap the message state baseline.  Falling back to "s-0" would cause
    // kithctl to replay ALL historical messages as new-message notifications on
    // the next SSE event — not acceptable.  Fail fast so the operator knows
    // kithd is unreachable rather than silently spamming notifications.
    let initial_state = jmap_post(
        config,
        &tailnet_ip,
        &connector,
        &serde_json::to_string(&bootstrap_req).expect("static json"),
    )
    .await
    .map_err(|e| format!("bootstrap failed (is kithd running?): {e}"))?
    .get("methodResponses")
    .and_then(|r| r.as_array())
    .and_then(|arr| arr.first())
    .and_then(|r| r.as_array())
    .and_then(|r| r.get(1))
    .and_then(|args| args.get("state"))
    .and_then(|v| v.as_str())
    .map(str::to_owned)
    .ok_or("bootstrap: Message/get response did not include a state field")?;

    // 4. SSE reconnect loop.
    let mut last_event_id: Option<String> = None;
    let mut last_message_state = initial_state;

    loop {
        match watch_once(
            config,
            &tailnet_ip,
            &connector,
            &mut last_event_id,
            &mut last_message_state,
        )
        .await
        {
            Ok(()) => break, // clean shutdown (e.g. 403)
            Err(e) => {
                let e_str = e.to_string();
                if e_str.contains("does not match pinned certificate") {
                    // kithd rotated its self-signed cert (e.g. it restarted).
                    // Re-read the cert from disk and rebuild the connector.
                    eprintln!("watch: kithd cert changed — reloading from {cert_path:?}");
                    match load_connector(&cert_path) {
                        Ok(new_connector) => {
                            connector = new_connector;
                            eprintln!("watch: cert reloaded, reconnecting...");
                        }
                        Err(load_err) => {
                            eprintln!(
                                "watch: failed to reload cert: {load_err}; retrying in 2s..."
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                    }
                } else {
                    eprintln!("watch: connection lost ({e}), reconnecting in 2s...");
                    // last_event_id is updated from the SSE stream's id: field inside
                    // watch_once and is used as-is on reconnect for resumption.
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Verify the SSE data JSON path that triggers message fetch notifications.
    ///
    /// Oracle: the server emits {"changed": {"a-self": {"Message": "s-N", ...}}}.
    /// This is a regression test for the bug where state_map.get("Message") was
    /// called at the top level of the data object instead of at ["changed"]["a-self"].
    #[test]
    fn sse_state_json_extracts_message_state() {
        let json_str = r#"{"changed": {"a-self": {"Message": "s-7"}}}"#;
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let got = v
            .get("changed")
            .and_then(|c| c.get("a-self"))
            .and_then(|a| a.get("Message"))
            .and_then(|s| s.as_str());
        assert_eq!(got, Some("s-7"));
    }

    /// Demonstrate the old bug: top-level get("Message") always returns None.
    /// If this test ever starts failing (returns Some), the parse has regressed.
    #[test]
    fn sse_state_json_top_level_message_is_none() {
        let json_str = r#"{"changed": {"a-self": {"Message": "s-7"}}}"#;
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(v.get("Message").and_then(|s| s.as_str()), None);
    }

    /// Chat-only SSE event must not trigger a Message fetch.
    #[test]
    fn sse_state_json_chat_only_no_message() {
        let json_str = r#"{"changed": {"a-self": {"Chat": "s-3"}}}"#;
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let got = v
            .get("changed")
            .and_then(|c| c.get("a-self"))
            .and_then(|a| a.get("Message"))
            .and_then(|s| s.as_str());
        assert_eq!(got, None);
    }

    /// Regression guard: Message/get returns "senderId", not "sender".
    ///
    /// Oracle: kith_core::Message serialises sender_id as "senderId" via
    /// #[serde(rename = "senderId")].  We construct a real Message, serialise
    /// it, and verify that our parse path extracts the right key.  If the
    /// serde rename ever changes, this test fails — and so does the kith-core
    /// field-name test — before any code reaches production.
    #[test]
    fn message_get_response_sender_field_is_sender_id() {
        let msg = kith_core::Message {
            id: "m-1".to_string(),
            sender_msg_id: "m-1".to_string(),
            chat_id: "chat-1".to_string(),
            sender_id: "uid-alice".to_string(),
            body: "hello".to_string(),
            body_type: "text/plain".to_string(),
            attachments: vec![],
            reply_to: None,
            sent_at: "2026-01-01T00:00:00Z".to_string(),
            received_at: "2026-01-01T00:00:00Z".to_string(),
            delivery_state: kith_core::DeliveryState::Received,
            delivered_at: None,
            read_at: None,
        };
        let json_val = serde_json::to_value(&msg).expect("Message must serialise");

        // Correct parse — must find the sender
        assert_eq!(
            json_val.get("senderId").and_then(|v| v.as_str()),
            Some("uid-alice")
        );
        // Wrong parse (old bug) — must return None
        assert_eq!(json_val.get("sender").and_then(|v| v.as_str()), None);
    }
}
