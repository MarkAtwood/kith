use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Duration;

use crate::Config;

/// RAII guard that removes a file on drop unless disarmed.
///
/// Used to clean up the pre-created backup stub file if any step after
/// `Connection::open` fails (e.g. `Backup::new` or `backup.step`).
struct CleanupGuard<'a> {
    path: &'a std::path::Path,
    armed: bool,
}

impl<'a> CleanupGuard<'a> {
    fn new(path: &'a std::path::Path) -> Self {
        Self { path, armed: true }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

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
            // Pre-create the file with mode 0o600 before SQLite opens it.
            // Connection::open would create the file with the process umask (typically
            // 0o644), leaving a TOCTOU window where the backup DB is world-readable.
            // Creating the file first (with create_new so we detect races) ensures
            // SQLite inherits the restricted permissions.
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&dest_path)?;
            let mut dst = rusqlite::Connection::open(&dest_path).inspect_err(|_| {
                // Clean up the pre-created stub file so the user can retry without
                // hitting the "destination already exists" guard.
                let _ = std::fs::remove_file(&dest_path);
            })?;
            // Guard covers failures from Backup::new and backup.step onwards.
            // If any of those return Err via ?, the stub file is removed so
            // the user can retry without hitting the "already exists" guard.
            let cleanup = CleanupGuard::new(&dest_path);
            let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
            const PAGES_PER_STEP: i32 = 100;
            const PAUSE: Duration = Duration::from_millis(250);
            const MAX_BUSY_RETRIES: u32 = 20;
            let mut busy_attempts: u32 = 0;
            loop {
                match backup.step(PAGES_PER_STEP)? {
                    rusqlite::backup::StepResult::Done => {
                        cleanup.disarm();
                        break;
                    }
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
