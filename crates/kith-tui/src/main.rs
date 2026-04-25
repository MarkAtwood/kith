use std::io::{self, stdout};

use clap::Parser;
use crossterm::{execute, terminal};
use ratatui::{backend::CrosstermBackend, Terminal};

use kith_tui::app::{AppState, ConnectionStatus};
use kith_tui::client;
use kith_tui::event;

#[derive(Parser, Debug)]
#[command(name = "kith-tui")]
struct Args {
    /// kithd base URL (e.g. https://100.64.0.1:8008)
    #[arg(long)]
    url: String,
    /// Path to kithd TLS certificate in DER format
    #[arg(long)]
    cert: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if !args.url.starts_with("https://") {
        eprintln!("--url must start with https://");
        return Err("invalid url".into());
    }

    let cert_der = client::read_cert_der(&args.cert)?;
    let http_client = client::build_client(&cert_der)?;

    // Install panic hook BEFORE entering raw mode so the terminal is always
    // restored even if a panic occurs inside the event loop.
    std::panic::set_hook(Box::new(|info| {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), terminal::LeaveAlternateScreen);
        eprintln!("panic: {info}");
    }));

    terminal::enable_raw_mode()?;
    execute!(stdout(), terminal::EnterAlternateScreen)?;

    let result = run_app(&http_client, &args.url).await;

    // Cleanup: always runs regardless of whether run_app returned Ok or Err,
    // including when fetch_session fails before the terminal is used.
    let _ = execute!(io::stdout(), crossterm::cursor::Show);
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), terminal::LeaveAlternateScreen);

    result?;
    Ok(())
}

async fn run_app(
    http_client: &reqwest::Client,
    url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let size = terminal.size()?;
    let mut state = AppState::new();
    state.terminal_size = (size.width, size.height);
    state.connection_status = ConnectionStatus::Connecting;

    let session = client::fetch_session(http_client, url).await?;
    if session.owner_user_id.is_empty() {
        return Err("server did not return ownerUserId in session response".into());
    }
    state.owner_user_id = session.owner_user_id.clone();
    let (sse_rx, sse_status_rx, _sse_handle) =
        client::spawn_sse(http_client.clone(), session.event_source_url.clone());

    event::run(
        &mut terminal,
        &mut state,
        http_client.clone(),
        session.api_url.clone(),
        sse_rx,
        sse_status_rx,
    )
    .await
}
