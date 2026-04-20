# Kith

**Tailnet-native chat. Mailboxes among kith.**

Kith is a self-hosted chat system built on Tailscale. Every participant runs their own mailbox daemon on a node they control; mailboxes talk directly to each other over the overlay. There is no central service, no central operator, no central plaintext store.

---

## Prerequisites

- Tailscale installed and authenticated on every node that will run `kithd`
- `tailscaled` running and reachable at `/var/run/tailscale/tailscaled.sock`
- A Tailscale node tagged `tag:kithd` for each user's mailbox (see ACL section)
- Linux (musl binary; glibc build requires Rust toolchain)

---

## Quickstart

```bash
# 1. Install and start Tailscale if you haven't already
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# 2. Download the kithd binary
curl -fsSL https://github.com/yourorg/kith/releases/latest/download/kithd-x86_64-unknown-linux-musl \
  -o /usr/local/bin/kithd
chmod +x /usr/local/bin/kithd

# 3. Install and start the service
sudo install -m 644 contrib/kithd.service /etc/systemd/system/kithd.service
sudo systemctl daemon-reload
sudo systemctl enable --now kithd

# 4. Open the web client
# kithd binds to your Tailscale interface only. Open:
#   https://<your-tailscale-ip>:443
# Auth is automatic via Tailscale whois — no login required.
```

---

## How it works

Every user runs exactly one `kithd` instance on a Tailscale node they own. Clients connect only to their own mailbox. Mailboxes deliver to each other over the Tailscale overlay.

```
   Alice's devices                         Bob's devices
   ┌──────────┐                            ┌──────────┐
   │  phone   │                            │  laptop  │
   │  laptop  │─── Tailscale overlay ──────│  phone   │
   │  tablet  │                            └──────────┘
   └────┬─────┘                                 │
        │                                       │
        │                                       │
   ┌────▼──────────┐      overlay          ┌────▼──────────┐
   │  alice-kith   │◄─────────────────────►│   bob-kith    │
   │  (Tailscale   │   mailbox protocol    │  (Tailscale   │
   │   node Alice  │                       │   node Bob    │
   │   owns)       │                       │   owns)       │
   └───────────────┘                       └───────────────┘
```

**Both online, direct path available:** Alice's client sends to `alice-kith`, which delivers directly to `bob-kith` over the overlay. Bob's client receives via EventSource push to his own mailbox.

**Bob offline:** `alice-kith` delivers to `bob-kith`, which queues the message. Bob's clients pull on next connect. If `bob-kith` itself is unreachable, `alice-kith` retries with exponential backoff.

**Multi-device:** All of Bob's devices connect to `bob-kith`. The mailbox fans out to all active clients. Per-device read cursors are tracked in the mailbox. No cross-device sync protocol needed; the mailbox is the sync point.

### Identity

A user is a Tailscale identity from the tailnet's identity provider. A mailbox is a Tailscale node tagged `tag:kithd`, owned by exactly one user. There are no passwords, no app-level accounts, no JWTs, no OAuth, no session tokens. Clients authenticate to their own mailbox via Tailscale's `WhoIs` on the TCP connection. Peer mailboxes authenticate the same way.

---

## External chat

Alice wants to chat with Carol, who is in a different tailnet.

1. Alice shares `alice-kith` out to Carol's Tailscale identity using Tailscale's node-sharing feature.
2. Carol shares `carol-kith` out to Alice's identity.
3. Each mailbox's ACL now permits the other's identity. Chat works.

There is no invite flow in the app. There is no pending/accepted/revoked state machine. The Tailscale sharing UI is the entire workflow. `kithd` reads the current ACL state and reflects it.

If Carol doesn't use Tailscale, she can't chat with Alice. That is the product. The friction is the feature.

---

## Deployment shapes

**Home server / NAS**
Run `kithd` as a systemd service alongside `tailscaled`. Data lives on your disk. This is the recommended shape for personal use.

**Small VPS**
Always-online mailbox. Note: the VPS host operator can read your data at rest. Kith v1 does not provide E2EE against the host; per-user E2EE is planned for v2. If you rent a VPS for this, name that in your threat model.

**Laptop-only**
Works. Not ideal — your mailbox is offline when the lid is closed, so incoming messages queue on the sender's side until you reconnect.

**Org / shared host**
One `kithd` per user, always. Use a systemd template unit with per-user data directories. See the Org section below.

---

## For orgs

### Systemd template unit

Save as `/etc/systemd/system/kithd@.service`:

```ini
[Unit]
Description=Kith mailbox daemon for %i
After=network-online.target tailscaled@%i.service
Requires=tailscaled@%i.service

[Service]
Type=notify
User=kith-%i
Group=kith
Environment=KITHD_DATA_DIR=/var/lib/kith/%i
Environment=KITHD_TAILSCALED_SOCKET=/var/run/tailscale/%i/tailscaled.sock
ExecStart=/usr/bin/kithd
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Provision a new user:

```bash
sudo systemctl enable --now kithd@alice
sudo systemctl enable --now kithd@bob
```

Each user gets a separate SQLite database in `/var/lib/kith/<username>/`. No user can query another's data. There is no admin read path, by design.

### Tailscale ACL

For an org where every member should be able to chat with every other member:

```hujson
{
  "tagOwners": { "tag:kithd": ["autogroup:member"] },
  "acls": [
    { "action": "accept", "src": ["autogroup:member"], "dst": ["tag:kithd:443"] }
  ]
}
```

For stricter compartmentalization (Finance can't reach Engineering, etc.), write more specific ACLs. Standard Tailscale/Headscale policy machinery applies; `kithd` has no opinion.

### What org admins do not get

Named explicitly to avoid confusion:

- No admin read access to user messages.

---

## Trust model and encryption

All overlay traffic is WireGuard-encrypted end-to-end between Tailscale nodes.

**In scope:** passive network observers on the public internet, malicious nodes outside the tailnet, compromised co-tenants on shared hosts, casual inspection of local disk by non-root users, impersonation via stolen node keys (partially mitigated by Tailnet Lock).

**Out of scope:** Tailscale Inc. as adversary when deployed on their service (they control the coordination plane and DERP relays), root on the mailbox host (they own the data), endpoint compromise of sender or recipient devices.

**DERP relay dependency (Tailscale Inc. deployment):** When direct WireGuard paths between nodes fail, traffic relays through Tailscale-operated DERP servers. DERP sees ciphertext, not plaintext — payloads remain WireGuard-encrypted between the nodes. But Tailscale Inc. controls the relay infrastructure. Do not deploy on Tailscale Inc.'s service if Tailscale Inc. is in your threat model.

**Tailnet Lock:** Recommended for deployments that want to defend against a malicious coordination server admitting unauthorized nodes. Tailnet Lock is a Tailscale Inc. feature; it is not available on Headscale.

---

## Headscale

To remove Tailscale Inc. from the trust graph entirely, deploy with [Headscale](https://headscale.net/). `kithd` talks only to the local `tailscaled` via LocalAPI and is agnostic to which control plane backs it.

With Headscale + self-hosted DERP:
- No Tailscale Inc. in the coordination or relay path.
- ACLs are managed by whoever runs the Headscale server.
- Custom DERP maps let you point at relay servers you operate.

**Headscale limitation:** There is no cross-instance federation ([headscale#1370](https://github.com/juanfont/headscale/issues/1370)). Cross-tailnet chat between two independently-run Headscale instances is not supported. Users who want to chat across instances must join a common Headscale server. This is a Headscale limitation, not a Kith limitation.

The reference deployment for the strongest trust properties: Headscale + self-hosted DERP.

---

## Building from source

Requires Rust stable (1.80 or later recommended).

```bash
# Build
cargo build --release

# Static musl binary for servers (recommended)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# ARM64 (NAS, Raspberry Pi, etc.)
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

Quality gates — run before every commit:

```bash
cargo fmt --all
cargo clippy --all-features -- -D warnings
cargo test
```

---

## What Kith is not

These are permanent non-goals, not deferred features:

- **No central service.** No kith.app, no cloud relay, no managed offering.
- **No multi-tenant daemon.** One `kithd` per user, always.
- **No admin read access.** Operators cannot read user messages. This is not a limitation to be engineered around; it is the point.
- **No federation to non-Tailscale networks.** No email bridges, no SMS gateways, no XMPP, no Matrix federation.
- **No discovery.** You cannot find people you don't already know. Admission to your circle is a Tailscale admin action.
- **No voice or video.**
- **No public-internet endpoints.**

---

## Wire protocol

JMAP (RFC 8620 core) with custom capability `urn:kith:chat:1`. JSON over HTTPS, listener bound to tailnet interface only. The same endpoint serves both owner clients and peer mailboxes; they differ only in which methods are authorized.

See `kith-architecture.md` for the full protocol specification, data types, and schema.

---

## License

AGPL-3.0-or-later.

`kithd` is a network service; AGPL §13 is the license term designed for that topology. A modified `kithd` running as a service must make its source available to users interacting with it. JMAP clients that speak to `kithd` are not derivative works of `kithd`.
