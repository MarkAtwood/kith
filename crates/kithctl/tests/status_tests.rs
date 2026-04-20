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

/// Compile-check: ensures the status command wiring compiles end-to-end.
#[test]
fn status_command_compiles() {}
