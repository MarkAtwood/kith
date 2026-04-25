use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use kith_core::AuthError;
use serde::{Deserialize, Deserializer};
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::UnixStream;

/// Default path for the Tailscale LocalAPI Unix socket.
pub const DEFAULT_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

/// The local node's own identity as returned inside the `/localapi/v0/status` response.
///
/// Only the fields kithd needs are decoded; all other fields in the `Self`
/// object are silently ignored.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SelfPeer {
    /// The Tailscale user ID of the node's owner.
    ///
    /// This is an opaque identifier — store and compare, never parse.
    /// Numeric in Tailscale Inc. deployments; may differ on Headscale.
    /// Serialized as a JSON number in the API response; serde decodes it
    /// into a String via the `deserialize_as_string` helper.
    #[serde(rename = "UserID", default, deserialize_with = "deserialize_as_string")]
    pub user_id: String,
}

/// Deserialize a JSON value (number or string) into a `String`.
///
/// Tailscale's `/status` endpoint represents `UserID` as a JSON number
/// (e.g. `12345`), not a quoted string.  This helper accepts both forms
/// so the struct works regardless of the serialization variant used by the
/// server.
fn deserialize_as_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct StringOrNumber;

    impl<'de> Visitor<'de> for StringOrNumber {
        type Value = String;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or integer")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
            Ok(v.to_owned())
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<String, E> {
            Ok(v.to_string())
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<String, E> {
            Ok(v.to_string())
        }
    }

    deserializer.deserialize_any(StringOrNumber)
}

/// Deserialize a DNS name, stripping the trailing `.` that Tailscale appends.
///
/// Tailscale's `/status` endpoint returns fully-qualified DNS names with a
/// trailing dot (e.g. `"bob-laptop.tail-test.ts.net."`). This helper strips
/// the trailing dot so callers receive a clean hostname string.
fn strip_trailing_dot<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let s = String::deserialize(d)?;
    if s.ends_with('.') {
        Ok(s[..s.len() - 1].to_owned())
    } else {
        Ok(s)
    }
}

/// A remote peer node as returned inside the `Peer` map of the
/// `/localapi/v0/status` response.
///
/// Only the fields kithd needs are decoded; all other fields in each peer
/// object are silently ignored.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PeerNode {
    /// The Tailscale user ID of the node's owner.
    ///
    /// Opaque identifier — store and compare, never parse.
    #[serde(rename = "UserID", default, deserialize_with = "deserialize_as_string")]
    pub user_id: String,
    /// The fully-qualified DNS name of the node, with the trailing dot removed.
    #[serde(rename = "DNSName", default, deserialize_with = "strip_trailing_dot")]
    pub dns_name: String,
    /// The node's tailnet IP addresses (IPv4 and/or IPv6).
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
}

/// Minimal subset of the Tailscale LocalAPI `/localapi/v0/status` response.
///
/// Only the fields kithd needs are decoded. The full response contains many
/// additional fields (Peer, User, …) which are silently ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct StatusResponse {
    #[serde(rename = "TailscaleIPs", default)]
    pub tailscale_ips: Vec<String>,
    #[serde(rename = "BackendState", default)]
    pub backend_state: String,
    /// The local node's own identity within the tailnet.
    ///
    /// `None` if the `Self` key is absent from the JSON (e.g. tailscaled
    /// is running but not yet logged in).
    #[serde(rename = "Self", default)]
    pub self_node: SelfPeer,
    /// All remote peer nodes in the tailnet, keyed by node key (opaque string).
    #[serde(rename = "Peer", default)]
    pub peers: std::collections::HashMap<String, PeerNode>,
}

impl StatusResponse {
    /// Returns all peer nodes, deduplicated by `user_id`, skipping any whose
    /// `user_id` matches `local_user_id`.
    ///
    /// A single Tailscale user may have multiple nodes (laptop, phone, …).
    /// Nodes are sorted by `dns_name` before deduplication so that the chosen
    /// node is deterministic: when a user has multiple devices the one with the
    /// lexicographically smallest `dns_name` is always selected.
    pub fn peer_nodes_excluding(&self, local_user_id: &str) -> Vec<&PeerNode> {
        // Sort by dns_name first so that HashMap's non-deterministic iteration
        // order does not affect which node is chosen for multi-device users.
        let mut nodes: Vec<&PeerNode> = self.peers.values().collect();
        nodes.sort_by(|a, b| a.dns_name.cmp(&b.dns_name));

        let mut seen = std::collections::HashSet::new();
        nodes
            .into_iter()
            .filter(|p| {
                !p.user_id.is_empty()
                    && p.user_id != local_user_id
                    && seen.insert(p.user_id.clone())
            })
            .collect()
    }
}

/// A Tailscale node as returned by the LocalAPI `/whois` endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WhoIsNode {
    pub name: String,
}

/// A Tailscale user profile as returned by the LocalAPI `/whois` endpoint.
///
/// `id` is opaque — store and compare, never parse or interpret its format.
/// `display_name` may be absent or empty (Headscale without OIDC); callers
/// should fall back to `login_name`, then to `id`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserProfile {
    #[serde(rename = "ID")]
    pub id: String,
    pub login_name: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// The response from the Tailscale LocalAPI `GET /localapi/v0/whois` endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WhoIsResponse {
    pub node: WhoIsNode,
    pub user_profile: UserProfile,
}

/// Timeout for each LocalAPI HTTP request.
///
/// tailscaled is local (Unix socket); 5 seconds is generous. If tailscaled
/// does not respond within this window, kithd returns an auth error rather
/// than blocking the request thread indefinitely.
const LOCAL_API_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// TTL for cached WhoIs responses.
///
/// 30 seconds balances identity freshness against tailscaled round-trip cost.
/// Tailscale identity changes (node removal, user re-auth) are rare; a 30-second
/// window is acceptable given the security model (the TCP peer address is still
/// verified per-request by the OS network stack).
const WHOIS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Hard cap on cache entries.
///
/// `retain()` removes TTL-expired entries on every write, so in steady state
/// the cache is bounded by (distinct active IPs × TTL-window).  The cap
/// provides a safety valve for bursts of unique source addresses (e.g. a large
/// tailnet or rapid IP churn): when the cap is exceeded after TTL eviction,
/// the entire cache is cleared.  A full clear causes a brief spike in LocalAPI
/// calls but avoids unbounded memory growth.  1024 is far above any realistic
/// Phase 1 tailnet size.
const WHOIS_CACHE_MAX: usize = 1024;

/// Maximum response body size for a Status response (10 MiB).
///
/// Status includes the full peer map; large tailnets (thousands of nodes)
/// can produce multi-MiB responses. 10 MiB is generous for current tailnets
/// while still preventing unbounded allocation. This limit is enforced during
/// streaming via `http_body_util::Limited`, preventing allocation of oversized
/// responses before the JSON parser runs. Do not raise without re-evaluating
/// the security boundary.
const STATUS_MAX_BYTES: usize = 10 * 1024 * 1024;

/// Maximum response body size for a WhoIs response (100 KiB).
///
/// A real WhoIs response is ~1–2 KiB. This limit is enforced during streaming
/// via `http_body_util::Limited`, preventing allocation of oversized responses
/// before the JSON parser runs. Do not raise without re-evaluating the
/// security boundary.
const WHOIS_MAX_BYTES: usize = 102_400;

/// Connect to the Tailscale LocalAPI Unix socket, issue a single GET request,
/// and return the response body as raw bytes.
///
/// The call is wrapped in [`LOCAL_API_TIMEOUT`]. On any error — connection,
/// handshake, HTTP, or body-size — an [`AuthError::WhoIsFailed`] is returned
/// with a context prefix that matches the per-operation naming convention used
/// throughout this module (`"connect: …"`, `"handshake: …"`, etc.).
///
/// `max_bytes` caps the response body via `http_body_util::Limited`; responses
/// that would exceed it are rejected before the full body is buffered.
async fn call_local_api(
    socket_path: &Path,
    uri: &str,
    max_bytes: usize,
) -> Result<Bytes, AuthError> {
    use AuthError::WhoIsFailed;

    let socket_path = socket_path.to_path_buf();
    let uri = uri.to_owned();

    tokio::time::timeout(LOCAL_API_TIMEOUT, async move {
        let stream = UnixStream::connect(&socket_path)
            .await
            .map_err(|e| WhoIsFailed(format!("connect: {e}")))?;

        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| WhoIsFailed(format!("handshake: {e}")))?;

        // Drive the connection in a background task; it finishes when sender is dropped.
        tokio::spawn(async move {
            // Ignore the result: connection errors surface through the sender.
            let _ = conn.await;
        });

        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            // LocalAPI requires a Host header; the value is ignored but must be present.
            .header("Host", "local")
            .body(Empty::<Bytes>::new())
            .map_err(|e| WhoIsFailed(format!("build request: {e}")))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| WhoIsFailed(format!("send request: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(WhoIsFailed(format!("HTTP {status}")));
        }

        // Collect body with a streaming size limit; Limited returns Err if the
        // limit is exceeded before the full body arrives.
        let body = http_body_util::Limited::new(resp.into_body(), max_bytes)
            .collect()
            .await
            .map_err(|_| WhoIsFailed(format!("response exceeds {max_bytes} byte limit")))?
            .to_bytes();

        Ok::<_, AuthError>(body)
    })
    .await
    .map_err(|_| WhoIsFailed("LocalAPI timeout: tailscaled unresponsive".into()))?
}

/// Client for the Tailscale LocalAPI Unix domain socket.
///
/// Each method opens a fresh connection. tailscaled is local, so connection
/// overhead is negligible and this avoids connection lifecycle complexity.
///
/// WhoIs responses are cached for [`WHOIS_CACHE_TTL`] to reduce round-trips to
/// tailscaled on every authenticated request. Failures are never cached. The
/// cache Mutex is never held across an `.await` point — it is acquired, read or
/// updated, and released before any async I/O.
pub struct LocalApiClient {
    socket_path: String,
    /// Short-TTL in-process WhoIs cache. Keyed by peer SocketAddr.
    whois_cache: std::sync::Mutex<
        std::collections::HashMap<std::net::SocketAddr, (std::time::Instant, WhoIsResponse)>,
    >,
}

impl LocalApiClient {
    /// Create a new client targeting the given Unix socket path.
    ///
    /// The default path on Linux is `/var/run/tailscale/tailscaled.sock`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            whois_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Call `GET /localapi/v0/status` and return the parsed response.
    ///
    /// Validates that the response contains at least one tailnet IP address,
    /// which confirms tailscaled is connected to the control plane.
    pub async fn status(&self) -> Result<StatusResponse, kith_core::AuthError> {
        use kith_core::AuthError::WhoIsFailed;

        let result = call_local_api(
            Path::new(&self.socket_path),
            "/localapi/v0/status",
            STATUS_MAX_BYTES,
        )
        .await?;

        let parsed: StatusResponse = serde_json::from_slice(&result)
            .map_err(|e| WhoIsFailed(format!("parse status JSON: {e}")))?;

        // NeedsLogin, NeedsNodeKey, NoState, and Stopped are known pre-authentication
        // states where Tailscale has not yet assigned a user identity. An empty UserID
        // in these states is expected and non-actionable. Any other state indicates a
        // possible misconfiguration or API change.
        if parsed.self_node.user_id.is_empty()
            && !matches!(
                parsed.backend_state.as_str(),
                "NeedsLogin" | "NeedsNodeKey" | "NoState" | "Stopped"
            )
        {
            tracing::warn!(
                backend_state = %parsed.backend_state,
                "Tailscale /status returned no UserID; KITHD_OWNER_ID must be set explicitly"
            );
        }

        if parsed.tailscale_ips.is_empty() {
            return Err(WhoIsFailed(
                "no tailnet IPs - is tailscale connected?".into(),
            ));
        }

        Ok(parsed)
    }

    /// Look up the Tailscale identity of the node at `addr`.
    ///
    /// Calls `GET /localapi/v0/whois?addr=<addr>` over the Unix socket and
    /// returns the parsed [`WhoIsResponse`]. Every network and parse error is
    /// wrapped in [`AuthError::WhoIsFailed`] with a context string that does
    /// not include the user ID value.
    ///
    /// Responses are cached for [`WHOIS_CACHE_TTL`] (30 seconds) to reduce
    /// round-trips to tailscaled on every authenticated request. Cache failures
    /// are never stored; only successful, validated responses are cached.
    ///
    /// The cache Mutex is never held across an `.await` — it is acquired,
    /// read or written, then released before any network I/O begins.
    pub async fn whois(&self, addr: SocketAddr) -> Result<WhoIsResponse, AuthError> {
        // Phase 1 (sync): check cache under a short lock scope, then release.
        // The guard is dropped before any `.await` so we never hold a Mutex across
        // an async suspension point.
        {
            let now = std::time::Instant::now();
            // Ignore a poisoned cache — treat it as a miss rather than crashing.
            if let Ok(cache) = self.whois_cache.lock() {
                if let Some((cached_at, cached_resp)) = cache.get(&addr) {
                    if now.duration_since(*cached_at) < WHOIS_CACHE_TTL {
                        return Ok(cached_resp.clone());
                    }
                }
            }
        } // lock guard dropped here — no Mutex held across the await below

        // Build the request path before the async call; addr does not appear
        // in error messages (per defensive rules).
        let uri = format!("/localapi/v0/whois?addr={addr}");

        let body = call_local_api(Path::new(&self.socket_path), &uri, WHOIS_MAX_BYTES).await?;

        let result: WhoIsResponse = serde_json::from_slice(&body)
            .map_err(|e| AuthError::WhoIsFailed(format!("parse whois JSON: {e}")))?;

        if result.user_profile.id.is_empty() {
            return Err(AuthError::WhoIsFailed("empty user_id".into()));
        }

        // Null bytes in identity strings can cause subtle bugs in downstream string
        // comparisons and SQL prepared statements. Reject early at the trust boundary.
        if result.user_profile.id.contains('\0') {
            return Err(AuthError::WhoIsFailed("null byte in user_id".into()));
        }

        // login_name is used downstream in Identity; reject null bytes for the same reason.
        if result.user_profile.login_name.contains('\0') {
            return Err(AuthError::WhoIsFailed("null byte in login_name".into()));
        }

        // node.name becomes mailbox_host in the DB; reject null bytes for the same reason.
        if result.node.name.contains('\0') {
            return Err(AuthError::WhoIsFailed("null byte in node.name".into()));
        }

        // display_name is optional but still stored; reject null bytes when present.
        if result
            .user_profile
            .display_name
            .as_deref()
            .is_some_and(|s| s.contains('\0'))
        {
            return Err(AuthError::WhoIsFailed("null byte in display_name".into()));
        }

        // Phase 2 (sync): store validated result in cache under a short lock scope.
        // Ignore a poisoned cache — missing a cache write is safe (next request will
        // call the real LocalAPI again). Never held across an `.await`.
        if let Ok(mut cache) = self.whois_cache.lock() {
            cache.retain(|_, (cached_at, _)| cached_at.elapsed() < WHOIS_CACHE_TTL);
            // If TTL eviction alone didn't bring us under the cap (e.g. a large
            // burst of unique source addresses within one TTL window), clear the
            // entire cache.  A full clear is safe — the next callers will just
            // re-populate via the LocalAPI.
            if cache.len() >= WHOIS_CACHE_MAX {
                cache.clear();
            }
            cache.insert(addr, (std::time::Instant::now(), result.clone()));
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ips_and_state() {
        let json = r#"{"TailscaleIPs":["100.64.0.1","fd7a::1"],"BackendState":"Running"}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(status.tailscale_ips, vec!["100.64.0.1", "fd7a::1"]);
        assert_eq!(status.backend_state, "Running");
    }

    #[test]
    fn empty_ips_is_valid() {
        let json = r#"{"TailscaleIPs":[],"BackendState":"NeedsLogin"}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert!(status.tailscale_ips.is_empty());
        assert_eq!(status.backend_state, "NeedsLogin");
    }

    #[test]
    fn extra_fields_are_ignored() {
        // Oracle: Tailscale LocalAPI spec — unknown fields must be silently ignored.
        // "Self" here has a different shape than SelfPeer; unknown subfields must not cause errors.
        let json = r#"{"TailscaleIPs":["100.64.0.1"],"BackendState":"Running","Self":{"UserID":99,"UnknownField":true},"Peer":{},"User":{}}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(status.tailscale_ips, vec!["100.64.0.1"]);
        assert_eq!(status.backend_state, "Running");
    }

    #[test]
    fn self_user_id_decoded_from_numeric() {
        // Oracle: Tailscale LocalAPI returns UserID as a JSON number (e.g. 12345),
        // not a quoted string.  Constructed from the Tailscale LocalAPI reference.
        let json =
            r#"{"TailscaleIPs":["100.64.0.1"],"BackendState":"Running","Self":{"UserID":12345}}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            status.self_node.user_id, "12345",
            "numeric UserID must be decoded as a String"
        );
    }

    #[test]
    fn self_user_id_decoded_from_string() {
        // Oracle: Headscale may return UserID as a quoted string; both forms must parse.
        let json = r#"{"TailscaleIPs":["100.64.0.1"],"BackendState":"Running","Self":{"UserID":"headscale-uid-abc"}}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            status.self_node.user_id, "headscale-uid-abc",
            "string UserID must be decoded as-is"
        );
    }

    #[test]
    fn self_absent_gives_empty_user_id() {
        // Oracle: if the "Self" key is absent (tailscaled not logged in), user_id defaults to "".
        let json = r#"{"TailscaleIPs":["100.64.0.1"],"BackendState":"NeedsLogin"}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(
            status.self_node.user_id, "",
            "absent Self key must yield empty user_id"
        );
    }

    #[test]
    fn whois_full_valid_response_parses() {
        // Fixture constructed from the Tailscale LocalAPI spec — not derived from
        // running the code under test.
        let json = r#"{
            "Node": {
                "Name": "mynode.tailnet.ts.net",
                "Addresses": ["100.64.0.1/32"]
            },
            "UserProfile": {
                "ID": "12345",
                "LoginName": "alice@example.com",
                "DisplayName": "Alice Smith",
                "ProfilePicURL": "https://example.com/pic.jpg"
            },
            "CapMap": {}
        }"#;

        let resp: WhoIsResponse = serde_json::from_str(json).expect("parse failed");

        assert_eq!(resp.node.name, "mynode.tailnet.ts.net");
        assert_eq!(resp.user_profile.id, "12345");
        assert_eq!(resp.user_profile.login_name, "alice@example.com");
        assert_eq!(
            resp.user_profile.display_name,
            Some("Alice Smith".to_string())
        );
    }

    #[test]
    fn whois_missing_optional_display_name_is_none() {
        // Fixture: UserProfile without DisplayName — matches Headscale without OIDC.
        let json = r#"{
            "Node": {"Name": "n"},
            "UserProfile": {"ID": "99", "LoginName": "bob@example.com"},
            "CapMap": {}
        }"#;

        let resp: WhoIsResponse = serde_json::from_str(json).expect("parse failed");

        assert_eq!(resp.user_profile.id, "99");
        assert_eq!(resp.user_profile.login_name, "bob@example.com");
        assert_eq!(resp.user_profile.display_name, None);
    }

    #[test]
    fn parse_status_with_peers() {
        // Oracle: Tailscale LocalAPI spec — Peer map keyed by node key, DNSName
        // has trailing dot. Constructed manually from the spec, not from running
        // the code under test.
        let json = r#"{
          "TailscaleIPs": ["100.64.0.1"],
          "BackendState": "Running",
          "Self": {"UserID": "1001"},
          "Peer": {
            "nodekey:abc": {"UserID": "2002", "DNSName": "bob-laptop.tail-test.ts.net.", "TailscaleIPs": ["100.64.0.2"]},
            "nodekey:def": {"UserID": "3003", "DNSName": "carol-pc.tail-test.ts.net.", "TailscaleIPs": ["100.64.0.3", "100.64.0.4"]}
          }
        }"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(status.peers.len(), 2);
        let bob = status.peers.values().find(|p| p.user_id == "2002").unwrap();
        assert_eq!(bob.dns_name, "bob-laptop.tail-test.ts.net"); // no trailing dot
        assert_eq!(bob.tailscale_ips, vec!["100.64.0.2"]);
    }

    #[test]
    fn parse_status_no_peers() {
        // Oracle: absent Peer key must yield an empty map (via `default`).
        let json = r#"{"TailscaleIPs": ["100.64.0.1"], "BackendState": "Running", "Self": {"UserID": "1001"}}"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        assert!(status.peers.is_empty());
    }

    #[test]
    fn peer_nodes_excluding_skips_self_and_deduplicates() {
        // Oracle: user 2002 appears on two nodes; peer_nodes_excluding must
        // return exactly one entry for user 2002 and must exclude user 1001
        // (the local user). Constructed manually from the spec.
        let json = r#"{
          "TailscaleIPs": ["100.64.0.1"],
          "BackendState": "Running",
          "Self": {"UserID": "1001"},
          "Peer": {
            "nodekey:abc": {"UserID": "2002", "DNSName": "bob-phone.ts.net.", "TailscaleIPs": ["100.64.0.2"]},
            "nodekey:def": {"UserID": "2002", "DNSName": "bob-laptop.ts.net.", "TailscaleIPs": ["100.64.0.3"]},
            "nodekey:ghi": {"UserID": "1001", "DNSName": "self-other.ts.net.", "TailscaleIPs": ["100.64.0.4"]}
          }
        }"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        let peers = status.peer_nodes_excluding("1001");
        assert_eq!(peers.len(), 1); // user 2002 deduplicated to 1; user 1001 excluded
        assert_eq!(peers[0].user_id, "2002");
    }

    // -----------------------------------------------------------------------
    // peer_nodes_excluding_multi_device_deterministic
    // Oracle: when a user has multiple nodes, the one with the
    // lexicographically smallest dns_name must always be selected.
    // "bob-laptop.ts.net." < "bob-phone.ts.net." alphabetically.
    // -----------------------------------------------------------------------
    #[test]
    fn peer_nodes_excluding_multi_device_deterministic() {
        let json = r#"{
          "TailscaleIPs": ["100.64.0.1"],
          "BackendState": "Running",
          "Self": {"UserID": "1001"},
          "Peer": {
            "nodekey:abc": {"UserID": "2002", "DNSName": "bob-phone.ts.net.", "TailscaleIPs": ["100.64.0.2"]},
            "nodekey:def": {"UserID": "2002", "DNSName": "bob-laptop.ts.net.", "TailscaleIPs": ["100.64.0.3"]}
          }
        }"#;
        let status: StatusResponse = serde_json::from_str(json).unwrap();
        let peers = status.peer_nodes_excluding("1001");
        assert_eq!(peers.len(), 1);
        // Oracle: "bob-laptop.ts.net" < "bob-phone.ts.net" (trailing dot stripped on parse) — laptop wins.
        assert_eq!(peers[0].dns_name, "bob-laptop.ts.net");
    }

    #[test]
    fn whois_extra_unknown_fields_are_ignored() {
        // Tailscale adds fields over time; forward-compat requires we tolerate them.
        let json = r#"{
            "Node": {"Name": "n", "UnknownField": 42},
            "UserProfile": {"ID": "1", "LoginName": "x", "FutureField": "y"},
            "SomeNewTopLevelKey": true
        }"#;

        let result: Result<WhoIsResponse, _> = serde_json::from_str(json);
        assert!(result.is_ok(), "unexpected parse error: {:?}", result.err());
    }
}
