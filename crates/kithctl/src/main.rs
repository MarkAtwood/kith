use std::path::PathBuf;

use clap::{Parser, Subcommand};
use kith_core::Contact;
use kith_store::Store;
use kith_tslocal::LocalApiClient;

use kithctl::Config;

#[derive(Parser)]
#[command(name = "kithctl", version, about = "kithd operator CLI")]
struct Cli {
    #[arg(long, global = true, help = "Path to kithd data directory")]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true, help = "Path to tailscaled Unix socket")]
    socket: Option<String>,
    #[arg(long, global = true, help = "kithd HTTPS port (default: 443)")]
    port: Option<u16>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show local Tailscale identity and tailnet IPs
    Status,
    /// Manage contacts
    Contacts {
        #[command(subcommand)]
        cmd: ContactsCmd,
    },
    /// Back up the mailbox database
    Backup {
        /// Destination path for backup file
        dest: Option<PathBuf>,
    },
    /// Watch for new messages and send desktop notifications
    Watch,
}

#[derive(Subcommand)]
enum ContactsCmd {
    /// List all contacts
    List,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mut config = Config::from_env();
    if let Some(d) = cli.data_dir {
        config.data_dir = d;
    }
    if let Some(s) = cli.socket {
        config.ts_socket = s;
    }
    if let Some(p) = cli.port {
        config.port = p;
    }
    let result = match cli.command {
        Commands::Status => cmd_status(&config).await,
        Commands::Contacts {
            cmd: ContactsCmd::List,
        } => cmd_contacts_list(&config),
        Commands::Backup { dest } => cmd_backup(&config, dest),
        Commands::Watch => cmd_watch(&config).await,
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_status(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let client = LocalApiClient::new(&config.ts_socket);
    let resp = client
        .status()
        .await
        .map_err(|e| format!("tailscaled not reachable: {e}"))?;
    println!("Backend state: {}", resp.backend_state);
    println!("User ID:       {}", resp.self_node.user_id);
    println!("Tailnet IPs:");
    if resp.tailscale_ips.is_empty() {
        println!("  (none)");
    } else {
        for ip in &resp.tailscale_ips {
            println!("  {ip}");
        }
    }
    Ok(())
}

/// Truncate `s` to at most `max` Unicode scalar values for fixed-width display.
///
/// If the string is longer than `max`, it is truncated to `max - 1` characters
/// and an ellipsis (`…`) is appended so the result fits within `max` columns.
fn fit_col(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() > max && max >= 2 {
        let truncated: String = chars[..max - 1].iter().collect();
        format!("{truncated}…")
    } else {
        s.to_string()
    }
}

fn cmd_contacts_list(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = config.db_path();
    if !db_path.exists() {
        return Err(
            format!("database not found at {db_path:?}; run kithd first to initialize").into(),
        );
    }
    let store = Store::open(&db_path)?;
    let contacts: Vec<Contact> = store.contacts().list()?;
    if contacts.is_empty() {
        println!("No contacts.");
        return Ok(());
    }
    println!(
        "{:<30} {:<25} {:<40} {:<8} LAST SEEN",
        "LOGIN", "DISPLAY NAME", "MAILBOX HOST", "BLOCKED"
    );
    println!("{}", "-".repeat(130));
    for contact in &contacts {
        let login_display = if contact.login.is_empty() {
            contact.tailscale_user_id.as_str()
        } else {
            contact.login.as_str()
        };
        let display_name = contact.display_name.as_deref().unwrap_or("-");
        let blocked_str = if contact.blocked { "BLOCKED" } else { "ok" };
        println!(
            "{:<30} {:<25} {:<40} {:<8} {}",
            fit_col(login_display, 30),
            fit_col(display_name, 25),
            fit_col(&contact.mailbox_host, 40),
            blocked_str,
            contact.last_seen_at
        );
    }
    println!();
    println!("{} contact(s)", contacts.len());
    Ok(())
}

fn cmd_backup(config: &Config, dest: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    kithctl::backup::run(config, dest)
}

async fn cmd_watch(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    kithctl::watch::cmd_watch(config).await
}
