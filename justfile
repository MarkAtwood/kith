# Run all three quality gates (format, lint, test)
check: fmt clippy test

# Format all crates — commit any changes this produces
fmt:
	cargo fmt --all

# Lint — all warnings are errors
clippy:
	cargo clippy --all-features -- -D warnings

# Full test suite
test:
	cargo test

# Cross-compile static musl binaries (requires: rustup target add x86_64-unknown-linux-musl)
build-musl-x86:
	cargo build --release --target x86_64-unknown-linux-musl

# Cross-compile static musl binary for ARM64/NAS/Pi (requires: rustup target add aarch64-unknown-linux-musl)
build-musl-aarch64:
	cargo build --release --target aarch64-unknown-linux-musl

# Both musl targets
build-musl: build-musl-x86 build-musl-aarch64

# Install rustup targets needed for musl cross-compile (run once per machine)
setup-targets:
	rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
