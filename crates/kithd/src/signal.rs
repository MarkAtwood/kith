/// Wait for a shutdown signal (SIGTERM or Ctrl-C).
///
/// Returns when the first signal is received. Designed to be passed to
/// `axum::serve(...).with_graceful_shutdown(signal::shutdown_signal())`.
///
/// On Unix: listens for SIGTERM (sent by systemd and `kill <pid>`) and
/// Ctrl-C (SIGINT). On non-Unix: listens for Ctrl-C only.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received Ctrl-C, initiating graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("received SIGTERM, initiating graceful shutdown");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify the function exists and has the correct return type signature.
    // We cannot actually call shutdown_signal() in a unit test (it would block).
    fn _assert_return_type() {
        let _: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
            Box::pin(shutdown_signal());
    }
}
