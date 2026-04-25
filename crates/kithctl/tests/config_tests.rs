//! Integration tests for kithctl Config.
//!
//! These tests define the CORRECT BEHAVIOR as specified in KITH-0fs.
//! They are the oracle: if the implementation diverges, the tests fail
//! and the implementation must be fixed.
//!
//! # Manual verification (CLI smoke test)
//!
//! Run the following commands after `cargo build -p kithctl` and verify
//! the output manually:
//!
//! ```text
//! kithctl --help
//! ```
//! Must list all four subcommands: `status`, `contacts`, `backup`, `watch`.
//!
//! ```text
//! kithctl --version
//! ```
//! Must print a version string (e.g. `kithctl 0.1.0`).
//!
//! ```text
//! kithctl contacts list --help
//! ```
//! Must show `--data-dir`, `--socket`, and `--port` flags.

use kithctl::Config;
use serial_test::serial;
use std::path::PathBuf;

/// Unset all three env vars, set HOME to a known temp path, and verify
/// that Config::from_env() returns the spec-mandated defaults.
#[test]
#[serial]
fn config_defaults() {
    // Arrange: clean slate — no overrides, controlled HOME.
    unsafe {
        std::env::remove_var("KITHD_DATA_DIR");
        std::env::remove_var("KITHD_TAILSCALED_SOCKET");
        std::env::remove_var("KITHD_PORT");
        std::env::remove_var("XDG_DATA_HOME");
        std::env::set_var("HOME", "/tmp/test_home");
    }

    // Act.
    let config = Config::from_env().expect("config must succeed in test");

    // Assert — independent oracle: spec says:
    //   data_dir  = $HOME/.local/share/kithd
    //   ts_socket = /var/run/tailscale/tailscaled.sock
    //   port      = 443
    assert_eq!(
        config.data_dir,
        PathBuf::from("/tmp/test_home/.local/share/kithd"),
        "data_dir should default to $HOME/.local/share/kithd"
    );
    assert_eq!(
        config.ts_socket, "/var/run/tailscale/tailscaled.sock",
        "ts_socket should default to /var/run/tailscale/tailscaled.sock"
    );
    assert_eq!(config.port, 443u16, "port should default to 443");
}

/// Set all three env vars to non-default values and verify that
/// Config::from_env() honours them.
#[test]
#[serial]
fn config_from_env() {
    // Arrange.
    unsafe {
        std::env::set_var("KITHD_DATA_DIR", "/custom/data");
        std::env::set_var("KITHD_TAILSCALED_SOCKET", "/run/ts.sock");
        std::env::set_var("KITHD_PORT", "8443");
        std::env::remove_var("XDG_DATA_HOME");
    }

    // Act.
    let config = Config::from_env().expect("config must succeed in test");

    // Assert — independent oracle: spec says env vars are read directly.
    assert_eq!(
        config.data_dir,
        PathBuf::from("/custom/data"),
        "data_dir should come from KITHD_DATA_DIR"
    );
    assert_eq!(
        config.ts_socket, "/run/ts.sock",
        "ts_socket should come from KITHD_TAILSCALED_SOCKET"
    );
    assert_eq!(config.port, 8443u16, "port should come from KITHD_PORT");

    // Cleanup — restore neutral state for subsequent tests.
    unsafe {
        std::env::remove_var("KITHD_DATA_DIR");
        std::env::remove_var("KITHD_TAILSCALED_SOCKET");
        std::env::remove_var("KITHD_PORT");
    }
}

/// Verify that db_path() and cert_path() return the correct derived paths.
///
/// Oracle: spec says
///   db_path()   = data_dir / "kith.db"
///   cert_path() = data_dir / "kith.crt"
#[test]
#[serial]
fn config_derived_paths() {
    // Arrange.
    unsafe {
        std::env::set_var("KITHD_DATA_DIR", "/mydata");
        std::env::remove_var("KITHD_TAILSCALED_SOCKET");
        std::env::remove_var("KITHD_PORT");
    }

    // Act.
    let config = Config::from_env().expect("config must succeed in test");

    // Assert.
    assert_eq!(
        config.db_path(),
        PathBuf::from("/mydata/kith.db"),
        "db_path() should be data_dir joined with 'kith.db'"
    );
    assert_eq!(
        config.cert_path(),
        PathBuf::from("/mydata/kith.crt"),
        "cert_path() should be data_dir joined with 'kith.crt'"
    );

    // Cleanup.
    unsafe {
        std::env::remove_var("KITHD_DATA_DIR");
    }
}

/// An invalid KITHD_PORT must NOT cause a panic; it must silently fall back
/// to the default port 443.
///
/// Oracle: spec says "KITHD_PORT parsed as u16 (default: 443)" — if the
/// value is not a valid u16, the safe choice is the default.
#[test]
#[serial]
fn config_invalid_port() {
    // Arrange.
    unsafe {
        std::env::remove_var("KITHD_DATA_DIR");
        std::env::remove_var("KITHD_TAILSCALED_SOCKET");
        std::env::set_var("KITHD_PORT", "notaport");
        std::env::remove_var("XDG_DATA_HOME");
        std::env::set_var("HOME", "/tmp/test_home");
    }

    // Act — must not panic.
    let config = Config::from_env().expect("config must succeed in test");

    // Assert — invalid port falls back to 443.
    assert_eq!(
        config.port, 443u16,
        "invalid KITHD_PORT must fall back to default 443 without panicking"
    );

    // Cleanup.
    unsafe {
        std::env::remove_var("KITHD_PORT");
    }
}
