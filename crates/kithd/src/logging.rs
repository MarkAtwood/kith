/// Initialize the global tracing subscriber.
///
/// Call this once at program start, before any tracing calls.
/// - If stderr is a terminal (TTY): human-readable format
/// - If stderr is not a TTY (systemd journal, log file): JSON format
///   Both: read RUST_LOG env var, default to "kithd=info,kith_peer=info"
///
/// # Panics
/// Panics if the subscriber has already been set.
pub fn init_logging() {
    use std::io::IsTerminal;
    let is_tty = std::io::stderr().is_terminal();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("kithd=info,kith_peer=info"));

    if is_tty {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .init();
    }
}

#[cfg(test)]
mod tests {
    // Verify the function signature compiles correctly.
    // We do NOT call init_logging() in tests — the global subscriber state is
    // process-wide and calling it from a test would interfere with other tests.
    #[allow(dead_code)]
    fn _signature_check() {
        let _f: fn() = super::init_logging;
    }
}
