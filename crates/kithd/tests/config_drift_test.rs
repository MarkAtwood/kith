/// Drift guard: every KITHD_* env var mentioned in the systemd service files
/// must appear in the known-vars list below.
///
/// Oracle: manual enumeration of all KITHD_* and legacy KITH_* vars accepted
/// by Config::from_env in crates/kithd/src/config.rs.
///
/// One-way check only: service vars ⊆ KNOWN_VARS.
/// Not all KNOWN_VARS are required to appear in the service files (e.g.
/// KITHD_BASE_URL and KITHD_BIND_ADDR are intentionally omitted there).
///
/// Update KNOWN_VARS when adding or renaming a KITHD_* variable in config.rs.
/// The reverse direction (config.rs var missing from service files) is intentional
/// for some vars and is not checked here — see the cross-reference comment in
/// Config::from_env for the full list.

#[test]
fn service_file_env_vars_exist_in_config_rs() {
    // Enumeration of all KITHD_* and legacy KITH_* vars accepted by Config::from_env.
    // This is the independent oracle for the drift check.
    const KNOWN_VARS: &[&str] = &[
        "KITHD_DATA_DIR",
        "KITHD_TAILSCALED_SOCKET",
        "KITHD_PORT",
        "KITHD_OWNER_ID",
        "KITHD_BASE_URL",
        "KITHD_BIND_ADDR",
        // Legacy names (still accepted with deprecation warning):
        "KITH_DB_PATH",
        "KITH_OWNER_ID",
        "KITH_BIND_ADDR",
    ];

    // CARGO_MANIFEST_DIR is set by cargo at compile time to the directory of
    // the crate's Cargo.toml (crates/kithd).  The service files live two
    // levels up under contrib/systemd/.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let service_path = format!("{manifest_dir}/../../contrib/systemd/kithd.service");
    let template_path = format!("{manifest_dir}/../../contrib/systemd/kithd@.service");

    let service = std::fs::read_to_string(&service_path)
        .unwrap_or_else(|e| panic!("cannot read {service_path}: {e}"));
    let template = std::fs::read_to_string(&template_path)
        .unwrap_or_else(|e| panic!("cannot read {template_path}: {e}"));

    for (file_name, content) in [("kithd.service", &service), ("kithd@.service", &template)] {
        for line in content.lines() {
            // Match lines of the form: Environment="KITHD_FOO=..."
            // (trimmed to handle any leading whitespace in the file)
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Environment=\"KITHD_") {
                let var_name = format!("KITHD_{}", rest.split('=').next().unwrap_or(""));
                assert!(
                    KNOWN_VARS.contains(&var_name.as_str()),
                    "{file_name} references env var {var_name} which is not in KNOWN_VARS; \
                     add it to KNOWN_VARS in tests/config_drift_test.rs"
                );
            }
        }
    }
}
