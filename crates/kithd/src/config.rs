/// Runtime configuration for kithd, parsed from environment variables.
pub struct Config {
    /// `KITHD_DATA_DIR` — base directory for all kithd data files.
    /// Default: `$XDG_DATA_HOME/kithd` or `$HOME/.local/share/kithd`
    pub data_dir: std::path::PathBuf,

    /// `KITHD_TAILSCALED_SOCKET` — path to tailscaled Unix socket.
    /// Default: `/var/run/tailscale/tailscaled.sock`
    pub ts_socket: String,

    /// `KITHD_PORT` — HTTPS listener port.
    /// Default: 443. Must parse as u16 in range 1–65535.
    pub port: u16,

    /// `KITHD_OWNER_ID` — Tailscale user ID of the mailbox owner.
    /// If absent, the caller must auto-detect or exit with an error.
    pub owner_id: Option<String>,

    /// `KITHD_BIND_ADDR` — development/test fallback bind address.
    ///
    /// When tailnet binding fails and this is set, kithd binds a plain HTTP
    /// (non-TLS) listener on this address instead. MUST NOT be set in production.
    /// Also accepted (deprecated): `KITH_BIND_ADDR`.
    /// Default: None (fail if tailnet is unavailable — production behavior).
    pub fallback_bind_addr: Option<String>,

    /// Derived: `data_dir/kith.db`
    pub db_path: std::path::PathBuf,

    /// `KITHD_DISCOVERY_INTERVAL_SECS` — how often the background discovery
    /// task probes tailnet peers for running kithd instances.
    /// Default: 300 seconds.  Minimum enforced: 60 seconds.
    pub discovery_interval_secs: u64,

    /// Derived: `data_dir/kith.crt`
    pub cert_path: std::path::PathBuf,

    /// Derived: `data_dir/kith.key`
    pub key_path: std::path::PathBuf,
}

impl Config {
    /// Parse config from environment variables.
    ///
    /// This function never panics. Invalid values are reported with `eprintln!`
    /// and defaults are used instead. The caller is responsible for creating
    /// `data_dir` if it does not exist.
    ///
    /// Env vars are also referenced in:
    ///   contrib/systemd/kithd.service
    ///   contrib/systemd/kithd@.service
    ///   contrib/README.md
    /// Keep in sync when adding or renaming variables.
    pub fn from_env() -> Self {
        let data_dir = Self::resolve_data_dir();
        let ts_socket = std::env::var("KITHD_TAILSCALED_SOCKET")
            .unwrap_or_else(|_| "/var/run/tailscale/tailscaled.sock".to_string());
        let port = Self::resolve_port();
        let owner_id = Self::resolve_owner_id();
        let fallback_bind_addr = Self::resolve_fallback_bind_addr();
        let discovery_interval_secs = {
            let raw = std::env::var("KITHD_DISCOVERY_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(300);
            if raw < 60 {
                eprintln!(
                    "kithd: KITHD_DISCOVERY_INTERVAL_SECS={} is below the 60s minimum; clamping to 60",
                    raw
                );
                60
            } else {
                raw
            }
        };

        let db_path = data_dir.join("kith.db");
        let cert_path = data_dir.join("kith.crt");
        let key_path = data_dir.join("kith.key");

        Config {
            data_dir,
            ts_socket,
            port,
            owner_id,
            fallback_bind_addr,
            discovery_interval_secs,
            db_path,
            cert_path,
            key_path,
        }
    }

    /// Resolve `data_dir` from env vars.
    ///
    /// Priority:
    /// 1. `KITHD_DATA_DIR`
    /// 2. Parent of `KITH_DB_PATH` (backward-compat, silent)
    /// 3. XDG default
    fn resolve_data_dir() -> std::path::PathBuf {
        if let Ok(val) = std::env::var("KITHD_DATA_DIR") {
            if !val.is_empty() {
                return std::path::PathBuf::from(val);
            }
        }

        // Backward-compat: if old KITH_DB_PATH is set, derive data_dir from its parent.
        if let Ok(db_path_str) = std::env::var("KITH_DB_PATH") {
            eprintln!("kithd: KITH_DB_PATH is deprecated, use KITHD_DATA_DIR");
            let db_path = std::path::PathBuf::from(&db_path_str);
            if let Some(parent) = db_path.parent() {
                if parent != std::path::Path::new("") {
                    return parent.to_path_buf();
                }
            }
        }

        Self::default_data_dir()
    }

    /// Resolve port from `KITHD_PORT`.
    ///
    /// Logs an `eprintln!` warning and returns 443 on invalid input.
    fn resolve_port() -> u16 {
        match std::env::var("KITHD_PORT") {
            Err(_) => 443,
            Ok(val) => match val.parse::<u32>() {
                Ok(n) if (1..=65535).contains(&n) => n as u16,
                _ => {
                    eprintln!("kithd: KITHD_PORT '{}' is invalid, using default 443", val);
                    443
                }
            },
        }
    }

    /// Resolve owner ID, with backward-compat fallback to `KITH_OWNER_ID`.
    fn resolve_owner_id() -> Option<String> {
        // Read each var once.
        let primary = std::env::var("KITHD_OWNER_ID").ok();
        if let Some(val) = primary {
            let trimmed = val.trim().to_string();
            return if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            };
        }
        // Legacy fallback.
        if let Ok(val) = std::env::var("KITH_OWNER_ID") {
            eprintln!("kithd: KITH_OWNER_ID is deprecated, use KITHD_OWNER_ID");
            let trimmed = val.trim().to_string();
            return if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            };
        }
        None
    }

    /// Resolve fallback bind address from `KITHD_BIND_ADDR`, with deprecated
    /// fallback to `KITH_BIND_ADDR`.
    ///
    /// Only loopback addresses (127.x.x.x / ::1) are accepted.  Non-loopback
    /// values are rejected with a fatal `eprintln!` and treated as absent so
    /// that an operator mistake cannot accidentally expose the API on a
    /// non-tailnet interface.
    fn resolve_fallback_bind_addr() -> Option<String> {
        let raw = if let Ok(val) = std::env::var("KITHD_BIND_ADDR") {
            if val.is_empty() {
                return None;
            }
            val
        } else if let Ok(val) = std::env::var("KITH_BIND_ADDR") {
            // KITH_BIND_ADDR is a deprecated alias retained for backwards compatibility.
            // New deployments should use KITHD_BIND_ADDR.
            eprintln!("kithd: KITH_BIND_ADDR is deprecated, use KITHD_BIND_ADDR");
            if val.is_empty() {
                return None;
            }
            val
        } else {
            return None;
        };

        // Reject non-loopback addresses.  KITHD_BIND_ADDR is for dev/test only;
        // allowing non-loopback exposes an unauthenticated plain-HTTP API to
        // non-tailnet networks, which violates the threat model.
        match raw.parse::<std::net::SocketAddr>() {
            Ok(addr) if addr.ip().is_loopback() => Some(raw),
            Ok(_) => {
                eprintln!(
                    "kithd: KITHD_BIND_ADDR '{}' is not a loopback address; \
                     only 127.x.x.x / [::1] are permitted. \
                     Setting ignored — binding on non-tailnet interfaces exposes \
                     the API without Tailscale identity authentication.",
                    raw
                );
                None
            }
            Err(_) => {
                eprintln!(
                    "kithd: KITHD_BIND_ADDR '{}' is not a valid socket address; ignoring",
                    raw
                );
                None
            }
        }
    }

    /// Compute the default data directory.
    ///
    /// Uses `$XDG_DATA_HOME/kithd` if set and non-empty, otherwise
    /// `$HOME/.local/share/kithd`.
    fn default_data_dir() -> std::path::PathBuf {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return std::path::PathBuf::from(xdg).join("kithd");
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("kithd")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Helper: remove a list of env vars, returning their previous values for
    /// restoration.
    fn take_vars(names: &[&str]) -> Vec<(String, Option<String>)> {
        names
            .iter()
            .map(|&name| {
                let prev = std::env::var(name).ok();
                // SAFETY: test-only; serial attribute prevents concurrent mutation.
                unsafe { std::env::remove_var(name) };
                (name.to_string(), prev)
            })
            .collect()
    }

    fn restore_vars(saved: Vec<(String, Option<String>)>) {
        for (name, val) in saved {
            match val {
                Some(v) => unsafe { std::env::set_var(name, v) },
                None => unsafe { std::env::remove_var(name) },
            }
        }
    }

    #[test]
    #[serial]
    fn test_defaults() {
        let saved = take_vars(&[
            "KITHD_DATA_DIR",
            "KITHD_TAILSCALED_SOCKET",
            "KITHD_PORT",
            "KITHD_OWNER_ID",
            "KITHD_BASE_URL",
            "KITHD_BIND_ADDR",
            "KITH_DB_PATH",
            "KITH_OWNER_ID",
            "KITH_BIND_ADDR",
        ]);

        let cfg = Config::from_env();

        assert!(
            cfg.data_dir.ends_with("kithd"),
            "data_dir should end with 'kithd', got {:?}",
            cfg.data_dir
        );
        assert_eq!(cfg.ts_socket, "/var/run/tailscale/tailscaled.sock");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.owner_id, None);
        assert_eq!(cfg.fallback_bind_addr, None);
        assert!(
            cfg.db_path.ends_with("kith.db"),
            "db_path should end with 'kith.db', got {:?}",
            cfg.db_path
        );
        assert!(
            cfg.cert_path.ends_with("kith.crt"),
            "cert_path should end with 'kith.crt', got {:?}",
            cfg.cert_path
        );
        assert!(
            cfg.key_path.ends_with("kith.key"),
            "key_path should end with 'kith.key', got {:?}",
            cfg.key_path
        );

        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn test_data_dir_deriving() {
        let saved = take_vars(&[
            "KITHD_DATA_DIR",
            "KITH_DB_PATH",
            "KITH_OWNER_ID",
            "KITHD_OWNER_ID",
        ]);

        unsafe { std::env::set_var("KITHD_DATA_DIR", "/tmp/testdir") };

        let cfg = Config::from_env();

        assert_eq!(cfg.data_dir, std::path::PathBuf::from("/tmp/testdir"));
        assert_eq!(
            cfg.db_path,
            std::path::PathBuf::from("/tmp/testdir/kith.db")
        );
        assert_eq!(
            cfg.cert_path,
            std::path::PathBuf::from("/tmp/testdir/kith.crt")
        );
        assert_eq!(
            cfg.key_path,
            std::path::PathBuf::from("/tmp/testdir/kith.key")
        );

        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn test_port_parsing() {
        let saved = take_vars(&["KITHD_PORT"]);

        unsafe { std::env::set_var("KITHD_PORT", "9443") };

        let cfg = Config::from_env();
        assert_eq!(cfg.port, 9443);

        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn test_invalid_port_uses_default() {
        let saved = take_vars(&["KITHD_PORT"]);

        unsafe { std::env::set_var("KITHD_PORT", "notanumber") };

        let cfg = Config::from_env();
        assert_eq!(cfg.port, 443);

        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn test_owner_id_trimming() {
        let saved = take_vars(&["KITHD_OWNER_ID", "KITH_OWNER_ID"]);

        unsafe { std::env::set_var("KITHD_OWNER_ID", " uid-123 ") };

        let cfg = Config::from_env();
        assert_eq!(cfg.owner_id, Some("uid-123".to_string()));

        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn test_empty_owner_id_becomes_none() {
        let saved = take_vars(&["KITHD_OWNER_ID", "KITH_OWNER_ID"]);

        unsafe { std::env::set_var("KITHD_OWNER_ID", "   ") };

        let cfg = Config::from_env();
        assert_eq!(cfg.owner_id, None);

        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn test_fallback_bind_addr_kithd_var() {
        let saved = take_vars(&["KITHD_BIND_ADDR", "KITH_BIND_ADDR"]);

        unsafe { std::env::set_var("KITHD_BIND_ADDR", "127.0.0.1:9090") };

        let cfg = Config::from_env();
        assert_eq!(cfg.fallback_bind_addr, Some("127.0.0.1:9090".to_string()));

        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn test_fallback_bind_addr_legacy_kith_var() {
        let saved = take_vars(&["KITHD_BIND_ADDR", "KITH_BIND_ADDR"]);

        // KITHD_BIND_ADDR absent; only the deprecated KITH_BIND_ADDR is set.
        unsafe { std::env::set_var("KITH_BIND_ADDR", "127.0.0.1:7070") };

        let cfg = Config::from_env();
        assert_eq!(cfg.fallback_bind_addr, Some("127.0.0.1:7070".to_string()));

        restore_vars(saved);
    }

    // -----------------------------------------------------------------------
    // KITH-o9x1.53: discovery interval clamp warning
    // Oracle: default is 300s; values ≥60 pass through; values <60 clamp to 60.
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn discovery_interval_below_minimum_clamps_to_60() {
        let saved = take_vars(&["KITHD_DISCOVERY_INTERVAL_SECS"]);
        unsafe { std::env::set_var("KITHD_DISCOVERY_INTERVAL_SECS", "5") };
        let cfg = Config::from_env();
        assert_eq!(
            cfg.discovery_interval_secs, 60,
            "value below 60 must clamp to 60"
        );
        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn discovery_interval_at_minimum_is_accepted() {
        let saved = take_vars(&["KITHD_DISCOVERY_INTERVAL_SECS"]);
        unsafe { std::env::set_var("KITHD_DISCOVERY_INTERVAL_SECS", "60") };
        let cfg = Config::from_env();
        assert_eq!(cfg.discovery_interval_secs, 60);
        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn discovery_interval_above_minimum_is_accepted() {
        let saved = take_vars(&["KITHD_DISCOVERY_INTERVAL_SECS"]);
        unsafe { std::env::set_var("KITHD_DISCOVERY_INTERVAL_SECS", "120") };
        let cfg = Config::from_env();
        assert_eq!(cfg.discovery_interval_secs, 120);
        restore_vars(saved);
    }

    // -----------------------------------------------------------------------
    // KITH-o9x1.55: non-loopback KITHD_BIND_ADDR rejected
    // Oracle: only 127.x.x.x / ::1 loopback addresses are accepted;
    // non-loopback is rejected (returns None) to protect the threat model.
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn fallback_bind_addr_non_loopback_is_rejected() {
        let saved = take_vars(&["KITHD_BIND_ADDR", "KITH_BIND_ADDR"]);
        unsafe { std::env::set_var("KITHD_BIND_ADDR", "0.0.0.0:8080") };
        let cfg = Config::from_env();
        assert_eq!(
            cfg.fallback_bind_addr, None,
            "non-loopback KITHD_BIND_ADDR must be rejected; got {:?}",
            cfg.fallback_bind_addr
        );
        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn fallback_bind_addr_public_ip_is_rejected() {
        let saved = take_vars(&["KITHD_BIND_ADDR", "KITH_BIND_ADDR"]);
        unsafe { std::env::set_var("KITHD_BIND_ADDR", "1.2.3.4:9000") };
        let cfg = Config::from_env();
        assert_eq!(cfg.fallback_bind_addr, None, "public IP must be rejected");
        restore_vars(saved);
    }

    #[test]
    #[serial]
    fn fallback_bind_addr_invalid_socket_addr_is_ignored() {
        let saved = take_vars(&["KITHD_BIND_ADDR", "KITH_BIND_ADDR"]);
        unsafe { std::env::set_var("KITHD_BIND_ADDR", "not-an-address") };
        let cfg = Config::from_env();
        assert_eq!(
            cfg.fallback_bind_addr, None,
            "unparseable address must be ignored"
        );
        restore_vars(saved);
    }

    /// A bare filename in the deprecated KITH_DB_PATH (no directory separator)
    /// has no meaningful parent, so kithd must fall back to the XDG data dir
    /// rather than using the working directory or an empty path component.
    #[test]
    #[serial]
    fn config_bare_filename_uses_xdg_default() {
        let saved = take_vars(&["KITHD_DATA_DIR", "KITH_DB_PATH", "XDG_DATA_HOME", "HOME"]);

        // Use a known HOME so the expected path is deterministic.
        unsafe { std::env::set_var("HOME", "/tmp/kith-test-home") };
        // XDG_DATA_HOME absent — forces the HOME/.local/share/kithd path.
        // KITHD_DATA_DIR absent — bare KITH_DB_PATH must not override the XDG default.
        unsafe { std::env::set_var("KITH_DB_PATH", "kith.db") };

        let cfg = Config::from_env();

        // The bare filename has no directory component, so resolve_data_dir()
        // skips the KITH_DB_PATH parent and returns the XDG default.
        assert_eq!(
            cfg.data_dir,
            std::path::PathBuf::from("/tmp/kith-test-home/.local/share/kithd"),
            "bare KITH_DB_PATH should not override the XDG data dir; got {:?}",
            cfg.data_dir
        );
        assert_eq!(
            cfg.db_path,
            std::path::PathBuf::from("/tmp/kith-test-home/.local/share/kithd/kith.db"),
            "db_path should be derived from the XDG data dir; got {:?}",
            cfg.db_path
        );

        restore_vars(saved);
    }
}
