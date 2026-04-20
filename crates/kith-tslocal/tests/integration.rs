/// Integration tests for `LocalApiClient::whois()` and `LocalApiClient::status()`.
///
/// Each test spawns a mock HTTP-over-Unix-socket server that writes a canned
/// HTTP/1.1 response then closes.  No real tailscaled required.
///
/// Oracle: JSON fixtures are hand-constructed from the Tailscale LocalAPI spec,
/// not derived from running the code under test.
use kith_tslocal::LocalApiClient;
use std::os::unix::fs::PermissionsExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

/// RAII guard that removes a Unix socket file on drop.
/// Ensures cleanup even when a test panics or returns early.
struct SocketGuard(String);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Unique socket path per test.  Incorporates the test name and process ID so
/// parallel test runs don't collide.
fn socket_path(test_name: &str) -> String {
    format!("/tmp/kith_test_{}_{}.sock", test_name, std::process::id())
}

/// Spawn a mock server that accepts exactly one connection, writes `response`,
/// then closes.  The caller is responsible for holding a `SocketGuard` so the
/// socket file is removed on test exit.
///
/// The caller must await a small yield or send the request promptly; the mock
/// exits after the first connection regardless.
async fn spawn_mock_server(path: &str, response: &'static [u8]) {
    // Remove stale socket file if present from a previous failed run.
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path).expect("bind mock socket");
    // Make it readable/writable by the current user only.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("set socket permissions");

    let response_bytes = response;
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Write the full response then close.  This is safe for test purposes
            // because hyper's HTTP/1.1 response parser reads and buffers the
            // complete response (headers + body up to Content-Length) before it
            // checks whether the connection is still open.  The immediate shutdown
            // is therefore invisible to the client after the bytes are delivered.
            let _ = stream.write_all(response_bytes).await;
            let _ = stream.shutdown().await;
        }
    });
}

// ── Test A — whois: valid 200 response, full parse ───────────────────────────

#[tokio::test]
async fn whois_valid_200_parses_user_profile() {
    const JSON: &[u8] = br#"{"Node":{"Name":"mynode.tailnet.ts.net","Addresses":["100.64.0.1/32"]},"UserProfile":{"ID":"12345","LoginName":"alice@example.com","DisplayName":"Alice"},"CapMap":{}}"#;
    let content_length = JSON.len();

    // Build the full HTTP/1.1 response in a static-lifetime buffer by leaking.
    // This avoids complex lifetime gymnastics in the spawn closure.
    let raw: Vec<u8> = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\nContent-Type: application/json\r\n\r\n"
    )
    .into_bytes()
    .into_iter()
    .chain(JSON.iter().copied())
    .collect();
    let raw: &'static [u8] = Box::leak(raw.into_boxed_slice());

    let path = socket_path("whois_valid_200");
    let _guard = SocketGuard(path.clone());
    spawn_mock_server(&path, raw).await;
    // Yield so the listener is ready before we connect.
    tokio::task::yield_now().await;

    let client = LocalApiClient::new(&path);
    let result = client.whois("127.0.0.1:12345".parse().unwrap()).await;

    let resp = result.expect("expected Ok from whois");
    assert_eq!(resp.user_profile.id, "12345");
    assert_eq!(resp.user_profile.login_name, "alice@example.com");
    assert_eq!(resp.node.name, "mynode.tailnet.ts.net");
}

// ── Test B — whois: HTTP 404 returns WhoIsFailed ─────────────────────────────

#[tokio::test]
async fn whois_404_returns_error() {
    let path = socket_path("whois_404");
    let _guard = SocketGuard(path.clone());
    spawn_mock_server(
        &path,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    tokio::task::yield_now().await;

    let client = LocalApiClient::new(&path);
    let result = client.whois("127.0.0.1:12345".parse().unwrap()).await;

    assert!(
        matches!(result, Err(kith_core::AuthError::WhoIsFailed(_))),
        "expected WhoIsFailed, got {result:?}"
    );
}

// ── Test C — socket not found ─────────────────────────────────────────────────

#[tokio::test]
async fn missing_socket_returns_error_whois() {
    let client = LocalApiClient::new("/tmp/nonexistent_kith_test_socket_xyz.sock");
    let result = client.whois("127.0.0.1:12345".parse().unwrap()).await;
    assert!(
        matches!(result, Err(kith_core::AuthError::WhoIsFailed(_))),
        "expected WhoIsFailed, got {result:?}"
    );
}

#[tokio::test]
async fn missing_socket_returns_error_status() {
    let client = LocalApiClient::new("/tmp/nonexistent_kith_test_socket_xyz.sock");
    let result = client.status().await;
    assert!(
        matches!(result, Err(kith_core::AuthError::WhoIsFailed(_))),
        "expected WhoIsFailed, got {result:?}"
    );
}

// ── Test D — status: valid 200 response ──────────────────────────────────────

#[tokio::test]
async fn status_valid_200_parses_ips() {
    const JSON: &[u8] = br#"{"TailscaleIPs":["100.64.0.1","fd7a::1"],"BackendState":"Running"}"#;
    let content_length = JSON.len();

    let raw: Vec<u8> = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\nContent-Type: application/json\r\n\r\n"
    )
    .into_bytes()
    .into_iter()
    .chain(JSON.iter().copied())
    .collect();
    let raw: &'static [u8] = Box::leak(raw.into_boxed_slice());

    let path = socket_path("status_valid_200");
    let _guard = SocketGuard(path.clone());
    spawn_mock_server(&path, raw).await;
    tokio::task::yield_now().await;

    let client = LocalApiClient::new(&path);
    let result = client.status().await;

    let resp = result.expect("expected Ok from status");
    assert_eq!(resp.tailscale_ips, vec!["100.64.0.1", "fd7a::1"]);
    assert_eq!(resp.backend_state, "Running");
}

// ── Test E — status: empty TailscaleIPs is rejected ──────────────────────────

#[tokio::test]
async fn status_empty_ips_returns_error() {
    const JSON: &[u8] = br#"{"TailscaleIPs":[],"BackendState":"NeedsLogin"}"#;
    let content_length = JSON.len();

    let raw: Vec<u8> = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\nContent-Type: application/json\r\n\r\n"
    )
    .into_bytes()
    .into_iter()
    .chain(JSON.iter().copied())
    .collect();
    let raw: &'static [u8] = Box::leak(raw.into_boxed_slice());

    let path = socket_path("status_empty_ips");
    let _guard = SocketGuard(path.clone());
    spawn_mock_server(&path, raw).await;
    tokio::task::yield_now().await;

    let client = LocalApiClient::new(&path);
    let result = client.status().await;

    assert!(
        matches!(result, Err(kith_core::AuthError::WhoIsFailed(_))),
        "expected WhoIsFailed for empty IPs, got {result:?}"
    );
}

// ── Test F — whois: null byte in login_name is rejected ──────────────────────

#[tokio::test]
async fn whois_null_byte_in_login_name_is_rejected() {
    // JSON \u0000 encodes a null byte inside the LoginName string.
    // Oracle: hand-constructed fixture — the check is a security invariant, not
    // derived from running the code under test.
    const JSON: &[u8] = b"{\"Node\":{\"Name\":\"n\"},\"UserProfile\":{\"ID\":\"42\",\"LoginName\":\"bad\\u0000user\"},\"CapMap\":{}}";
    let content_length = JSON.len();

    let raw: Vec<u8> = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {content_length}\r\nContent-Type: application/json\r\n\r\n"
    )
    .into_bytes()
    .into_iter()
    .chain(JSON.iter().copied())
    .collect();
    let raw: &'static [u8] = Box::leak(raw.into_boxed_slice());

    let path = socket_path("whois_null_login_name");
    let _guard = SocketGuard(path.clone());
    spawn_mock_server(&path, raw).await;
    tokio::task::yield_now().await;

    let client = LocalApiClient::new(&path);
    let result = client.whois("127.0.0.1:12345".parse().unwrap()).await;

    assert!(
        matches!(result, Err(kith_core::AuthError::WhoIsFailed(_))),
        "expected WhoIsFailed for null byte in login_name, got {result:?}"
    );
}

// ── Test G — whois: body over 102_400 bytes is rejected ──────────────────────

#[tokio::test]
async fn whois_oversized_body_returns_error() {
    // 110_000 bytes exceeds WHOIS_MAX_BYTES (102_400).
    const BODY_LEN: usize = 110_000;

    let mut body = Vec::with_capacity(BODY_LEN);
    body.extend(std::iter::repeat_n(b'x', BODY_LEN));

    let raw: Vec<u8> = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {BODY_LEN}\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes()
    .into_iter()
    .chain(body)
    .collect();
    let raw: &'static [u8] = Box::leak(raw.into_boxed_slice());

    let path = socket_path("whois_oversized");
    let _guard = SocketGuard(path.clone());
    spawn_mock_server(&path, raw).await;
    tokio::task::yield_now().await;

    let client = LocalApiClient::new(&path);
    let result = client.whois("127.0.0.1:12345".parse().unwrap()).await;

    assert!(
        matches!(result, Err(kith_core::AuthError::WhoIsFailed(_))),
        "expected WhoIsFailed for oversized body, got {result:?}"
    );
}
