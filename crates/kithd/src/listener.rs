use kith_core::AuthError;
use kith_tslocal::{LocalApiClient, StatusResponse};
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpListener;

/// Abstraction over the Tailscale Status call, enabling test doubles.
///
/// Implemented for [`LocalApiClient`] in production and for mock structs in tests.
/// Use with concrete generics (`T: StatusProvider`) rather than `dyn StatusProvider`
/// to avoid a dependency on `async-trait`.
pub trait StatusProvider {
    fn status(&self)
        -> impl std::future::Future<Output = Result<StatusResponse, AuthError>> + Send;
}

impl StatusProvider for LocalApiClient {
    fn status(
        &self,
    ) -> impl std::future::Future<Output = Result<StatusResponse, AuthError>> + Send {
        LocalApiClient::status(self)
    }
}

/// Errors from [`bind_tailnet_listeners`].
#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("tailscale is unavailable: {0}")]
    TailscaleUnavailable(#[source] AuthError),
    #[error("tailscaled returned no tailnet IPs")]
    NoTailnetIps,
    #[error("all bind attempts failed")]
    AllBindsFailed,
}

/// Bind a TCP listener on each of the provided tailnet IP strings at the given port.
///
/// This is the binding-only half of [`bind_tailnet_listeners`]. Call it when you
/// already have a `StatusResponse` (e.g. from an earlier status call) to avoid
/// a redundant round-trip to tailscaled.
///
/// Never binds to 0.0.0.0 or ::. If `ips` is empty or all binds fail, returns an error.
pub async fn bind_to_ips(ips: &[String], port: u16) -> Result<Vec<TcpListener>, ListenerError> {
    if ips.is_empty() {
        return Err(ListenerError::NoTailnetIps);
    }

    let mut listeners = Vec::new();
    for ip_str in ips {
        match ip_str.parse::<IpAddr>() {
            Err(e) => {
                tracing::warn!("skipping unparseable tailnet IP '{}': {}", ip_str, e);
            }
            Ok(ip) => {
                if ip.is_unspecified() {
                    tracing::error!(
                        %ip,
                        "refusing to bind to unspecified address (would expose kithd on all \
                         interfaces); check tailscaled /status output"
                    );
                    continue;
                }
                let addr = SocketAddr::new(ip, port);
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        tracing::info!("kithd: listening on {} (tailnet)", addr);
                        listeners.push(listener);
                    }
                    Err(e) => {
                        tracing::warn!("failed to bind {}: {}", addr, e);
                    }
                }
            }
        }
    }

    if listeners.is_empty() {
        return Err(ListenerError::AllBindsFailed);
    }

    Ok(listeners)
}

/// Bind a TCP listener on each tailnet IP at the given port.
///
/// Calls LocalAPI /status to get the node's tailnet IPs, then delegates to
/// [`bind_to_ips`]. Logs each successful and failed bind.
///
/// Never binds to 0.0.0.0 or ::. If no IPs are available or all
/// binds fail, returns an error.
pub async fn bind_tailnet_listeners<T: StatusProvider>(
    ts: &T,
    port: u16,
) -> Result<Vec<TcpListener>, ListenerError> {
    let status = ts
        .status()
        .await
        .map_err(ListenerError::TailscaleUnavailable)?;
    bind_to_ips(&status.tailscale_ips, port).await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockStatus {
        ips: Vec<String>,
        fail: bool,
    }

    impl StatusProvider for MockStatus {
        fn status(
            &self,
        ) -> impl std::future::Future<Output = Result<StatusResponse, AuthError>> + Send {
            let result: Result<StatusResponse, AuthError> = if self.fail {
                Err(AuthError::WhoIsFailed("mock".into()))
            } else {
                Ok(StatusResponse {
                    tailscale_ips: self.ips.clone(),
                    backend_state: "Running".into(),
                    self_node: kith_tslocal::SelfPeer::default(),
                    peers: Default::default(),
                })
            };
            async move { result }
        }
    }

    // -----------------------------------------------------------------------
    // test_one_ip_binds_one_listener: mock returns ["127.0.0.1"], port 0
    // Oracle: one listener is returned; OS assigns a free port.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_one_ip_binds_one_listener() {
        let mock = MockStatus {
            ips: vec!["127.0.0.1".into()],
            fail: false,
        };
        let listeners = bind_tailnet_listeners(&mock, 0)
            .await
            .expect("should bind one listener");
        assert_eq!(listeners.len(), 1);
    }

    // -----------------------------------------------------------------------
    // test_empty_ips_returns_error: mock returns [], no IPs from tailscaled
    // Oracle: NoTailnetIps error variant.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_empty_ips_returns_error() {
        let mock = MockStatus {
            ips: vec![],
            fail: false,
        };
        let err = bind_tailnet_listeners(&mock, 0)
            .await
            .expect_err("empty IPs must fail");
        assert!(
            matches!(err, ListenerError::NoTailnetIps),
            "expected NoTailnetIps, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // test_status_fail_returns_error: mock returns error from status()
    // Oracle: TailscaleUnavailable error variant wrapping the AuthError.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_status_fail_returns_error() {
        let mock = MockStatus {
            ips: vec![],
            fail: true,
        };
        let err = bind_tailnet_listeners(&mock, 0)
            .await
            .expect_err("status failure must propagate");
        assert!(
            matches!(err, ListenerError::TailscaleUnavailable(_)),
            "expected TailscaleUnavailable, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // test_invalid_ip_is_skipped: mock returns ["notanip", "127.0.0.1"]
    // Oracle: 1 listener (invalid string is skipped), not an error.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_invalid_ip_is_skipped() {
        let mock = MockStatus {
            ips: vec!["notanip".into(), "127.0.0.1".into()],
            fail: false,
        };
        let listeners = bind_tailnet_listeners(&mock, 0)
            .await
            .expect("should bind one listener despite invalid IP");
        assert_eq!(listeners.len(), 1);
    }

    // -----------------------------------------------------------------------
    // test_all_invalid_ips_returns_error: mock returns only unparseable strings
    // Oracle: AllBindsFailed error variant (nothing to bind after filtering).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_all_invalid_ips_returns_error() {
        let mock = MockStatus {
            ips: vec!["notanip".into(), "alsonotanip".into()],
            fail: false,
        };
        let err = bind_tailnet_listeners(&mock, 0)
            .await
            .expect_err("all invalid IPs must fail");
        assert!(
            matches!(err, ListenerError::AllBindsFailed),
            "expected AllBindsFailed, got {err:?}"
        );
    }
}
