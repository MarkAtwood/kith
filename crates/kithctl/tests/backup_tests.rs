//! Integration tests for `kithctl backup`.
//!
//! These tests exercise the live SQLite backup logic against real on-disk
//! databases. The oracle for correctness is the value we inserted before
//! the backup — not any value queried back from the source.

use std::path::PathBuf;

use kithctl::Config;

/// Build a minimal Config pointing at a given data directory.
fn config_for_dir(data_dir: PathBuf) -> Config {
    Config {
        data_dir,
        ts_socket: "/var/run/tailscale/tailscaled.sock".to_string(),
        port: 443,
    }
}

/// Test 1: A backup of a populated SQLite database produces a valid copy.
///
/// Oracle: the string "hello" was inserted into the source before the
/// backup ran. We query the backup file with an independent connection
/// and assert the value equals "hello" — not whatever the source
/// happens to return at query time.
#[test]
fn backup_creates_valid_database() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let src_path = data_dir.join("kith.db");
    let dest_path = tmp.path().join("kith.db.backup");

    // Create source DB with one table and one row.
    {
        let conn = rusqlite::Connection::open(&src_path).expect("open src");
        conn.execute_batch(
            "CREATE TABLE t (x TEXT NOT NULL);
             INSERT INTO t VALUES ('hello');",
        )
        .expect("setup src");
    }

    // Run the backup.
    let config = config_for_dir(data_dir);
    kithctl::backup::run(&config, Some(dest_path.clone())).expect("backup::run");

    // Verify the destination file exists.
    assert!(dest_path.exists(), "dest file should exist after backup");

    // Verify permissions are 0o600.
    let meta = std::fs::metadata(&dest_path).expect("metadata");
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "dest file must have mode 0o600");

    // Open the backup with an independent connection and query the row.
    let dest_conn = rusqlite::Connection::open(&dest_path).expect("open dest");
    let val: String = dest_conn
        .query_row("SELECT x FROM t", [], |row| row.get(0))
        .expect("query dest");

    // Oracle: the string we inserted, not queried from source.
    assert_eq!(val, "hello", "backup must contain the inserted row");
}

/// Test 2: backup refuses to overwrite an existing destination file.
///
/// Oracle: the error message must contain "already exists".
#[test]
fn backup_refuses_to_overwrite_existing_dest() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let src_path = data_dir.join("kith.db");
    let dest_path = tmp.path().join("dest.db");

    // Create a minimal source DB.
    {
        let conn = rusqlite::Connection::open(&src_path).expect("open src");
        conn.execute_batch("CREATE TABLE t (x TEXT);")
            .expect("setup src");
    }

    // Create the destination file so it pre-exists.
    std::fs::write(&dest_path, b"").expect("create dest");

    // Attempt backup — must return an error.
    let config = config_for_dir(data_dir);
    let err = kithctl::backup::run(&config, Some(dest_path))
        .expect_err("backup should fail when dest exists");

    assert!(
        err.to_string().contains("already exists"),
        "error message must mention 'already exists', got: {err}"
    );
}
