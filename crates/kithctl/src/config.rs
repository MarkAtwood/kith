use std::path::PathBuf;

pub struct Config {
    pub data_dir: PathBuf,
    pub ts_socket: String,
    pub port: u16,
}

impl Config {
    pub fn from_env() -> Self {
        let data_dir = if let Ok(dir) = std::env::var("KITHD_DATA_DIR") {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(xdg).join("kithd")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/share/kithd")
        } else {
            eprintln!("error: KITHD_DATA_DIR or HOME must be set");
            std::process::exit(1);
        };

        let ts_socket = std::env::var("KITHD_TAILSCALED_SOCKET")
            .unwrap_or_else(|_| "/var/run/tailscale/tailscaled.sock".to_string());

        let port = match std::env::var("KITHD_PORT") {
            Ok(val) => val.parse::<u16>().unwrap_or_else(|_| {
                eprintln!("warning: KITHD_PORT is not a valid port number; using 443");
                443
            }),
            Err(_) => 443,
        };

        Self {
            data_dir,
            ts_socket,
            port,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("kith.db")
    }

    pub fn cert_path(&self) -> PathBuf {
        self.data_dir.join("kith.crt")
    }
}
