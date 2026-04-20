# Deploying kithd

## Prerequisites

- Linux host with systemd
- [Tailscale](https://tailscale.com/) installed and running (`tailscaled` active)
- A Tailscale account with at least one node

## Quick Start (Single User)

### 1. Get the binary

Build from source (requires Rust + cargo-zigbuild for a static binary):

```bash
cargo install cargo-zigbuild
cargo zigbuild --release --target x86_64-unknown-linux-musl
# Binary: target/x86_64-unknown-linux-musl/release/kithd
```

For ARM64 (NAS, Raspberry Pi):

```bash
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

### 2. Install

```bash
sudo install -m 755 target/x86_64-unknown-linux-musl/release/kithd /usr/local/bin/kithd
```

### 3. Create the service user and data directory

```bash
sudo useradd --system --home /var/lib/kithd --shell /usr/sbin/nologin kithd
sudo mkdir -p /var/lib/kithd
sudo chown kithd:kithd /var/lib/kithd
sudo chmod 700 /var/lib/kithd
```

### 4. Install the systemd unit

```bash
sudo install -m 644 contrib/systemd/kithd.service /etc/systemd/system/kithd.service
sudo systemctl daemon-reload
```

### 5. Configure your owner ID (optional)

kithd auto-detects your Tailscale user ID on first start. To set it explicitly
(recommended on a shared host where multiple Tailscale users may be logged in):

```bash
# Get your Tailscale user ID
tailscale status --json | jq -r .Self.UserID

# Edit /etc/systemd/system/kithd.service and set:
# Environment="KITHD_OWNER_ID=<your-user-id>"
sudo systemctl daemon-reload
```

### 6. Start

```bash
sudo systemctl enable kithd
sudo systemctl start kithd
sudo systemctl status kithd
```

## First-Run Experience

On first start, kithd logs messages like:

```
kithd: auto-detected owner identity from Tailscale
Kith mailbox initialized. Add contacts in the web UI to start chatting.
kithd ready at https://100.64.0.1/
kithd ready at https://fd7a::1/
```

Open the URL shown in `kithd ready at https://...` in your browser. This is your
tailnet-only address — it is not accessible from the internet.

## Multi-User Deployment (Organization)

For multiple users on a shared host, use the template unit (`kithd@.service`).
Each instance runs as a dedicated system user with isolated data.

### Setup for user "alice"

```bash
# Install the template unit
sudo install -m 644 contrib/systemd/kithd@.service /etc/systemd/system/kithd@.service
sudo systemctl daemon-reload

# Create per-user data dir and system account
sudo useradd --system --home /var/lib/kithd/alice --shell /usr/sbin/nologin kith-alice
sudo mkdir -p /var/lib/kithd/alice
sudo chown kith-alice:kithd /var/lib/kithd/alice
sudo chmod 700 /var/lib/kithd/alice

# Set alice's Tailscale user ID in a drop-in override
sudo mkdir -p /etc/systemd/system/kithd@alice.service.d
sudo tee /etc/systemd/system/kithd@alice.service.d/owner.conf <<'EOF'
[Service]
Environment="KITHD_OWNER_ID=<alice-tailscale-user-id>"
EOF
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable kithd@alice
sudo systemctl start kithd@alice
```

Repeat for each user, substituting the username and Tailscale user ID.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `KITHD_DATA_DIR` | `~/.local/share/kithd` | Directory for SQLite DB and TLS certs |
| `KITHD_PORT` | `443` | HTTPS listener port (1–65535) |
| `KITHD_OWNER_ID` | *(auto-detected)* | Tailscale user ID of the mailbox owner |
| `KITHD_TAILSCALED_SOCKET` | `/var/run/tailscale/tailscaled.sock` | Path to tailscaled Unix socket |
| `RUST_LOG` | `kithd=info,kith_peer=info` | Log level (trace/debug/info/warn/error) |

`KITHD_OWNER_ID` is auto-detected from Tailscale on first start if not set. Set
it explicitly when running on a shared host or in a multi-user template deployment.

## Viewing Logs

```bash
# Follow live logs
sudo journalctl -u kithd -f

# Last 50 lines
sudo journalctl -u kithd -n 50 --no-pager

# For a template instance
sudo journalctl -u kithd@alice -f
```

## Troubleshooting

**Tailscale socket not found:**

```
Tailscale not available: <error>. Is tailscaled running? (sudo systemctl status tailscaled)
```

Check tailscaled is running: `sudo systemctl status tailscaled`

Check socket permissions: `ls -l /var/run/tailscale/tailscaled.sock`

The kithd service user must be able to read the socket; add it to the `tailscale`
group if needed.

**Port 443 permission denied:**

kithd binds to Tailscale virtual interfaces, not to physical NICs. No
`CAP_NET_BIND_SERVICE` is needed. If you see a bind error, verify the Tailscale
interface is up: `tailscale status`.

**TLS certificate regenerated on restart:**

kithd stores certs in `KITHD_DATA_DIR`. If the data dir is lost or recreated, a
new cert is generated. Tailscale peers do not validate the cert (Tailscale identity
is the trust anchor), so this is safe.

**Viewing the TLS certificate:**

```bash
openssl x509 -in /var/lib/kithd/kith.crt -text -noout
```

**Verify static binary (no runtime dependencies):**

```bash
ldd /usr/local/bin/kithd
# Expected: "not a dynamic executable"
```
