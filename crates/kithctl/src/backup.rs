use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use crate::Config;

fn backup_progress(p: rusqlite::backup::Progress) {
    eprint!(
        "\rBacking up... {}/{} pages",
        p.pagecount - p.remaining,
        p.pagecount
    );
}

/// Back up the mailbox database.
///
/// If `dest` is `Some`, performs a live SQLite online backup to that path.
/// If `dest` is `None`, prints recommended copy commands for the operator.
pub fn run(config: &Config, dest: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let db_path = config.db_path();
    match dest {
        Some(dest_path) => {
            if !db_path.exists() {
                return Err(format!("database not found at {db_path:?}; run kithd first").into());
            }
            if dest_path.exists() {
                return Err(
                    format!("destination {dest_path:?} already exists; remove it first").into(),
                );
            }
            let src = rusqlite::Connection::open_with_flags(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            let mut dst = rusqlite::Connection::open(&dest_path)?;
            std::fs::set_permissions(&dest_path, std::fs::Permissions::from_mode(0o600))?;
            let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
            const PAGES_PER_STEP: i32 = 100;
            const PAUSE: Duration = Duration::from_millis(250);
            const MAX_BUSY_RETRIES: u32 = 20;
            let mut busy_attempts: u32 = 0;
            loop {
                match backup.step(PAGES_PER_STEP)? {
                    rusqlite::backup::StepResult::Done => break,
                    rusqlite::backup::StepResult::More => {
                        backup_progress(backup.progress());
                        busy_attempts = 0;
                        std::thread::sleep(PAUSE);
                    }
                    _ => {
                        busy_attempts += 1;
                        if busy_attempts >= MAX_BUSY_RETRIES {
                            return Err(
                                "database is locked; kithd appears to be writing — try again in a moment".into()
                            );
                        }
                        std::thread::sleep(PAUSE);
                    }
                }
            }
            eprintln!();
            println!("Backup complete: {}", dest_path.display());
            println!(
                "Note: also backup attachments at {}/attachments if present",
                config.data_dir.display()
            );
        }
        None => {
            println!("# Live backup (safe while kithd is running):");
            println!("  kithctl backup --dest {}.backup", db_path.display());
            println!();
            println!("# Or stop kithd first, then copy the whole data directory:");
            println!(
                "  cp -a {} {}.backup",
                config.data_dir.display(),
                config.data_dir.display()
            );
            println!("# (includes database, TLS certs, and attachments)");
        }
    }
    Ok(())
}
