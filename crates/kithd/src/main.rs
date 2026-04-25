use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::service::TowerToHyperService;
use kith_attach::BlobStore;
use kith_events::make_channel;
use kith_store::Store;
use kith_tslocal::LocalApiClient;
use kithd::auth::WhoIsProvider;
use kithd::build_app;
use kithd::build_dispatcher;
use kithd::extractors::AppState;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tower::Service;

#[tokio::main]
async fn main() {
    // -----------------------------------------------------------------------
    // 1. Init logging -- must be first, before any tracing calls
    // -----------------------------------------------------------------------
    kithd::logging::init_logging();

    // -----------------------------------------------------------------------
    // 2. Config from environment
    // -----------------------------------------------------------------------
    let config = kithd::config::Config::from_env();

    // Extract fallback_bind_addr before config fields are partially moved.
    // Remains None in production (tailnet binding is mandatory); set only via
    // KITHD_BIND_ADDR for development/test without a real Tailscale network.
    let fallback_bind_addr = config.fallback_bind_addr;

    // -----------------------------------------------------------------------
    // 3. Tailscale LocalAPI client -- needed before owner_id resolution
    // -----------------------------------------------------------------------
    let ts = Arc::new(LocalApiClient::new(&config.ts_socket));

    // -----------------------------------------------------------------------
    // 4. Early Tailscale availability check
    //
    // We call status() once here and reuse the result for owner_id
    // auto-detection so we never make two round-trips to tailscaled.
    // -----------------------------------------------------------------------
    let early_status = ts.status().await;
    if let Err(ref e) = early_status {
        tracing::warn!(
            socket = %config.ts_socket,
            "Tailscale not available: {}. Is tailscaled running? \
             (sudo systemctl status tailscaled)",
            e
        );
    }

    // -----------------------------------------------------------------------
    // 5. Resolve owner_id -- env var takes priority; fall back to Tailscale
    // -----------------------------------------------------------------------
    let owner_id = match config.owner_id {
        Some(id) => id,
        None => match &early_status {
            Ok(status) => {
                let id = status.self_node.user_id.trim().to_string();
                if id.is_empty() {
                    eprintln!(
                        "kithd: KITHD_OWNER_ID is not set and Tailscale returned an empty \
                         user ID. Set KITHD_OWNER_ID explicitly \
                         (tailscale status --json | jq -r .Self.UserID)"
                    );
                    std::process::exit(1);
                }
                tracing::info!("auto-detected owner identity from Tailscale");
                id
            }
            Err(_) => {
                eprintln!(
                    "kithd: KITHD_OWNER_ID is not set and Tailscale is unavailable. \
                     Set KITHD_OWNER_ID to your Tailscale user ID \
                     (tailscale status --json | jq -r .Self.UserID)"
                );
                std::process::exit(1);
            }
        },
    };

    // -----------------------------------------------------------------------
    // 5a. Resolve owner_login from Tailscale WhoIs on the local node's own IP.
    //
    // We call WhoIs on the first tailnet IP so that tailscaled can resolve the
    // full UserProfile (including LoginName) for the owner.  This is a best-
    // effort lookup: if tailscaled is unavailable or returns an error, we fall
    // back to an empty string and the Session's ownerLogin field will be empty.
    // -----------------------------------------------------------------------
    let owner_login: String = match &early_status {
        Ok(status) if !status.tailscale_ips.is_empty() => {
            let ip_str = &status.tailscale_ips[0];
            match format!("{ip_str}:443").parse::<SocketAddr>() {
                Ok(addr) => match ts.whois(addr).await {
                    Ok(who) => who.user_profile.login_name,
                    Err(e) => {
                        tracing::warn!("could not resolve owner login via WhoIs: {e}");
                        String::new()
                    }
                },
                Err(_) => {
                    tracing::warn!("could not parse tailnet IP for owner WhoIs: {ip_str}");
                    String::new()
                }
            }
        }
        _ => String::new(),
    };

    // -----------------------------------------------------------------------
    // 6. Ensure data_dir exists
    // -----------------------------------------------------------------------
    std::fs::create_dir_all(&config.data_dir).unwrap_or_else(|e| {
        tracing::error!("cannot create data dir {:?}: {e}", config.data_dir);
        std::process::exit(1);
    });

    // -----------------------------------------------------------------------
    // 7. Open SQLite store
    // -----------------------------------------------------------------------
    let mut store = Store::open(&config.db_path).unwrap_or_else(|e| {
        tracing::error!("cannot open store {:?}: {e}", config.db_path);
        std::process::exit(1);
    });

    // -----------------------------------------------------------------------
    // 7a. First-run detection
    // -----------------------------------------------------------------------
    match store.is_first_run() {
        Ok(true) => tracing::info!(
            "Kith mailbox initialized. Add contacts in the web UI to start chatting."
        ),
        Ok(false) => {}
        Err(e) => {
            tracing::error!("first-run check failed: {e}");
            std::process::exit(1);
        }
    }

    // -----------------------------------------------------------------------
    // 7b. Startup summary
    // -----------------------------------------------------------------------
    tracing::info!(
        data_dir = ?config.data_dir,
        db_path = ?config.db_path,
        ts_socket = %config.ts_socket,
        port = config.port,
        owner_id = %owner_id,
        owner_login = %owner_login,
        "kithd starting"
    );

    // -----------------------------------------------------------------------
    // 7c. Initialize blob store
    // -----------------------------------------------------------------------
    let blob_dir = config.data_dir.join("blobs");
    let blob_store = Arc::new(BlobStore::new(&blob_dir));
    blob_store.init().unwrap_or_else(|e| {
        tracing::error!("cannot create blob dir {:?}: {e}", blob_dir);
        std::process::exit(1);
    });

    // -----------------------------------------------------------------------
    // 8. Events broadcast channel; wire into store
    // -----------------------------------------------------------------------
    // The initial receiver is dropped immediately; EventSource handlers call
    // tx.subscribe() per connection. The channel stays alive while events_tx
    // (held in AppState) is live.
    let (events_tx, _events_rx) = make_channel(64);
    store.set_events_tx(events_tx.clone());
    let store = Arc::new(Mutex::new(store));

    // -----------------------------------------------------------------------
    // 9. Build JMAP dispatcher and AppState
    // -----------------------------------------------------------------------
    let dispatcher = Arc::new(build_dispatcher(
        Arc::clone(&store),
        Arc::clone(&blob_store),
    ));

    let state = AppState {
        ts: Arc::clone(&ts),
        store: Arc::clone(&store),
        owner_id: owner_id.clone(),
        owner_login: owner_login.clone(),
        base_url: kithd::resolve_base_url(),
        events_tx,
        dispatcher,
        blob_store,
    };

    // -----------------------------------------------------------------------
    // 10. Build axum router
    // -----------------------------------------------------------------------
    let app = build_app(state).into_make_service_with_connect_info::<SocketAddr>();

    // -----------------------------------------------------------------------
    // 11. Spawn outbox worker with supervision — restart on panic.
    // -----------------------------------------------------------------------
    let store_for_outbox = Arc::clone(&store);
    let owner_id_for_outbox = owner_id.clone();
    tokio::spawn(async move {
        loop {
            let h = tokio::spawn(kith_peer::outbox_worker(
                Arc::clone(&store_for_outbox),
                kith_peer::PeerHttpClient::new(),
                owner_id_for_outbox.clone(),
            ));
            match h.await {
                Ok(_) => {
                    tracing::warn!("outbox_worker exited unexpectedly; restarting");
                }
                Err(e) => {
                    tracing::error!("outbox_worker panicked: {e:?}; restarting in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    });

    // -----------------------------------------------------------------------
    // 11a. Spawn peer discovery task
    // -----------------------------------------------------------------------
    kithd::discovery::spawn_discovery_task(
        Arc::clone(&ts),
        Arc::clone(&store),
        config.port,
        owner_id.clone(),
        config.discovery_interval_secs,
    );
    tracing::info!(
        "discovery: background task started (interval={}s)",
        config.discovery_interval_secs
    );

    // -----------------------------------------------------------------------
    // 12. Try tailnet binding + TLS; fall back to plain HTTP for development
    //
    // Reuse tailscale_ips from early_status (step 4) -- no second round-trip.
    // -----------------------------------------------------------------------
    let tailscale_ips = match &early_status {
        Ok(s) => s.tailscale_ips.clone(),
        Err(_) => vec![],
    };
    match kithd::listener::bind_to_ips(&tailscale_ips, config.port).await {
        Ok(listeners) => {
            // TLS path: load or generate self-signed cert, build acceptor
            let acceptor = kithd::tls::make_tls_acceptor(&config.cert_path, &config.key_path)
                .unwrap_or_else(|e| {
                    tracing::error!("TLS setup failed: {e}");
                    std::process::exit(1);
                });

            // Shutdown coordination for TLS accept loops
            let (shutdown_tx, shutdown_rx_proto) = tokio::sync::watch::channel(false);

            // In-flight connection tracking for graceful drain
            let in_flight = Arc::new(AtomicUsize::new(0));
            let drain_notify = Arc::new(tokio::sync::Notify::new());

            // Spawn an accept loop for each tailnet listener
            for listener in listeners {
                // Log the ready URL before moving the listener into the task.
                match listener.local_addr() {
                    Ok(addr) => tracing::info!("kithd ready at https://{}/", addr),
                    Err(e) => tracing::warn!("could not read listener local_addr: {e}"),
                }
                let acceptor = acceptor.clone();
                let mut make_svc = app.clone();
                let mut shutdown_rx = shutdown_rx_proto.clone();
                let in_flight_loop = Arc::clone(&in_flight);
                let drain_notify_loop = Arc::clone(&drain_notify);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            biased;
                            _ = shutdown_rx.changed() => {
                                tracing::debug!("accept loop received shutdown signal");
                                break;
                            }
                            result = listener.accept() => {
                                let (tcp, peer_addr) = match result {
                                    Ok(x) => x,
                                    Err(e) => {
                                        tracing::warn!("accept error on tailnet listener, retrying: {e}");
                                        continue;
                                    }
                                };
                                let tls = match acceptor.accept(tcp).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::warn!("TLS handshake failed from {peer_addr}: {e}");
                                        continue;
                                    }
                                };
                                let io = TokioIo::new(tls);
                                // Build a per-connection Service by passing the peer address to
                                // the MakeSvc layer, which wires it into the WhoIs auth middleware.
                                let svc = match make_svc.call(peer_addr).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        // IntoMakeServiceWithConnectInfo error is Infallible;
                                        // this branch is unreachable but satisfies the compiler.
                                        tracing::error!("make_service error: {e:?}");
                                        continue;
                                    }
                                };
                                let hyper_svc = TowerToHyperService::new(svc);
                                in_flight_loop.fetch_add(1, Ordering::Relaxed);
                                let in_flight_conn = Arc::clone(&in_flight_loop);
                                let notify_conn = Arc::clone(&drain_notify_loop);
                                tokio::spawn(async move {
                                    auto::Builder::new(TokioExecutor::new())
                                        .serve_connection(io, hyper_svc)
                                        .await
                                        .unwrap_or_else(|e| tracing::debug!("connection error: {e}"));
                                    if in_flight_conn.fetch_sub(1, Ordering::AcqRel) == 1 {
                                        notify_conn.notify_one();
                                    }
                                });
                            }
                        }
                    }
                });
            }

            // Wait for shutdown signal, then stop accept loops
            kithd::signal::shutdown_signal().await;
            tracing::info!("kithd: shutdown signal received, stopping accept loops");
            let _ = shutdown_tx.send(true);
            tracing::info!("kithd: stop accepting connections; draining in-flight requests");

            // Wait until all in-flight connections complete or timeout elapses
            let in_flight_drain = Arc::clone(&in_flight);
            let notify_drain = Arc::clone(&drain_notify);
            let drain = async move {
                loop {
                    // Register the waiter BEFORE reading the counter.  If the
                    // last connection calls notify_one() between our load and
                    // notified().await, the notification is already queued and
                    // will wake us immediately rather than being lost.
                    let notified = notify_drain.notified();
                    if in_flight_drain.load(Ordering::Acquire) == 0 {
                        break;
                    }
                    notified.await;
                }
            };
            tokio::select! {
                _ = drain => {
                    tracing::info!("kithd: all connections drained");
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    tracing::warn!(
                        remaining = in_flight.load(Ordering::Relaxed),
                        "kithd: graceful drain timeout, forcing shutdown"
                    );
                }
            }
            tracing::info!("kithd shutdown complete");
        }
        Err(e) => {
            // Only fall back to plain HTTP when KITHD_BIND_ADDR is explicitly
            // set (development/test without a real Tailscale network).  In
            // production (KITHD_BIND_ADDR unset), refuse to start rather than
            // silently serving the full API over an unauthenticated plaintext
            // loopback listener.
            let fallback_addr = match fallback_bind_addr {
                Some(addr) => addr,
                None => {
                    tracing::error!(
                        "tailnet binding failed ({e}); kithd requires a Tailscale network. \
                         Set KITHD_BIND_ADDR to enable a plain-HTTP dev fallback."
                    );
                    std::process::exit(1);
                }
            };
            tracing::warn!(
                "tailnet binding failed ({e}), falling back to plain HTTP on {fallback_addr}"
            );
            let listener = tokio::net::TcpListener::bind(&fallback_addr)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("fallback bind to {fallback_addr} failed: {e}");
                    std::process::exit(1);
                });
            match listener.local_addr() {
                Ok(addr) => tracing::info!("kithd ready at http://{}/", addr),
                Err(e) => tracing::warn!("could not read fallback listener local_addr: {e}"),
            }
            axum::serve(listener, app)
                .with_graceful_shutdown(kithd::signal::shutdown_signal())
                .await
                .unwrap_or_else(|e| tracing::error!("server error: {e}"));
        }
    }
}

// Compile-time check: AppState<LocalApiClient> satisfies WhoIsProvider bounds.
// This function is never called; it exists only to trigger a compile error if
// the production type drifts out of conformance with the WhoIsProvider trait.
#[allow(dead_code)]
fn _assert_local_api_client_implements_whois_provider() {
    fn _check<W: WhoIsProvider + Send + Sync + 'static>() {}
    _check::<LocalApiClient>();
}
