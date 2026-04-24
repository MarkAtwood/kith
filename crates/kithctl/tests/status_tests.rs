/// Manual verification: `kithctl status` prints `backend_state`, `user_id`, and tailnet IPs
/// when tailscaled is running. Example output:
///
/// ```text
/// Backend state: Running
/// User ID:       12345
/// Tailnet IPs:
///   100.64.0.1
///   fd7a::1
/// ```
///
/// When tailscaled is not reachable the command exits with:
///
/// ```text
/// error: tailscaled not reachable: WhoIs failed: connect to tailscaled socket: ...
/// ```

/// The status command calls LocalApiClient::status() and maps errors to an
/// "tailscaled not reachable" message. When the socket path does not exist,
/// status() must return Err (not panic or hang).
#[tokio::test]
async fn status_fails_when_tailscaled_socket_unreachable() {
    use kith_tslocal::LocalApiClient;
    let client = LocalApiClient::new("/nonexistent/tailscaled.sock");
    let result = client.status().await;
    assert!(
        result.is_err(),
        "status() should fail when socket path does not exist"
    );
}
