# Kith

**Tailnet-native chat. Mailboxes among kith.**

*Kith (Old English `cȳþþ`): one's friends, acquaintances, people known to one. The "kith" in "kith and kin" — those admitted to your circle.*

The name describes the social boundary of the system: messages travel among people you've already admitted to your overlay, not across the public internet. No strangers, no discovery, no central directory. Just kith.

Components and conventions:
- `kithd` — the mailbox daemon, one per user
- `kithctl` — local CLI for operators
- `urn:kith:chat:1` — JMAP capability URI
- Example hostnames throughout this document: `alice-kith.tail-xxxxx.ts.net`, `bob-kith.tail-yyyyy.ts.net` (users pick their own)

## Premise

Every participant runs their own mailbox on a Tailscale node they control. There is no central service, no central operator, no central plaintext store. The overlay is the network. Tailscale identity is user identity. Mailboxes talk to mailboxes.

External chat = share a specific mailbox node out of your tailnet (or accept a share from someone else's). That is the entire external-access model. It is a Tailscale admin action, not a workflow inside the app.

## License

AGPL-3.0-or-later. `kithd` is a network service; AGPL §13 is the license term designed for that topology. A modified `kithd` running as a service must make its source available to users interacting with it.

The AGPL's scope is bounded to the program itself and users interacting with it. It does not reach JMAP clients that talk to `kithd`, nor adjacent services in the operator's infrastructure — that broader "service stack" scope is what the SSPL was drafted to cover precisely because AGPL does not. Clients speaking JMAP to `kithd` are not derivative works of `kithd`.

## Threat model (explicit)

- **In scope:** passive network observers on the public internet, malicious nodes outside the tailnet, compromised co-tenants on shared hosts, casual inspection of local disk by non-root users, impersonation via stolen node keys (partially, via Tailnet Lock).
- **Out of scope:** Tailscale Inc. as adversary when deployed on Tailscale Inc.'s service (they operate the coordination plane and DERP relays). Root on the mailbox host (they own the data). Endpoint compromise of the sender or recipient device.
- **DERP dependency (Tailscale Inc. deployment):** when direct paths fail, traffic relays through Tailscale-operated DERP servers. Payloads are WireGuard-encrypted end-to-end between nodes. DERP sees ciphertext, not plaintext. Name this in the README; do not claim "zero dependency" on Tailscale Inc.
- **DERP dependency (Headscale deployment):** closes to zero. Headscale supports custom DERP maps; operators can run their own DERP servers (or use a curated non-Tailscale-Inc set). The "no Tailscale Inc. in the trust graph" property holds end-to-end only under Headscale + self-hosted DERP.
- **Tailnet Lock:** recommended for deployments that want to defend against a malicious coordination server admitting unauthorized nodes. Design works without it; Tailnet Lock is a deployment hardening choice. Note: Tailnet Lock is a Tailscale Inc. feature and is not available on Headscale at time of writing; Headscale deployments rely on operator control of the coordination server instead.

## Components

Exactly two things:

1. **Mailbox daemon (`kithd`).** One per user. Runs on a Tailscale node the user owns. Stores that user's messages. Speaks to other mailbox daemons over the overlay. Also serves that user's own clients.
2. **Client.** Web or native. Talks only to its owner's mailbox daemon. Never directly to another user's mailbox.

No central anything. No gateway node. No shared service tier.

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

## Identity

- A **user** is a Tailscale identity (email-shaped, from the tailnet's identity provider).
- A **mailbox** is a Tailscale node tagged `tag:mailbox`, owned by exactly one user.
- A **contact** is `{user_identity, mailbox_node_name}`. MagicDNS names are fine: `alice-kith.tail-xxxxx.ts.net`.
- No passwords. No app-level accounts. Client authenticates to its own mailbox via Tailscale `whois` on the local API, which returns the connecting peer's tailnet identity. Mailbox authenticates incoming peer connections the same way.

Concretely: when a mailbox receives a connection on its Tailscale interface, it calls `tailscale.LocalClient.WhoIs(ctx, remoteAddr)` and gets back `{UserProfile, Node}`. That's the caller's verified identity. No JWTs, no OAuth, no session tokens.

## Message flow

### Both online, direct path available
Alice's client → `alice-kith` → (Tailscale overlay) → `bob-kith` → Bob's client (via long-poll or WebSocket to his own mailbox).

### Bob offline
Alice's client → `alice-kith` → (Tailscale overlay, direct or DERP) → `bob-kith` queues message → Bob's client pulls on next connect.

`bob-kith` is always online (it's on a node Bob picked for this purpose: home server, NAS, small VPS, whatever). If `bob-kith` itself is offline, `alice-kith` retries with exponential backoff. Messages sit in `alice-kith`'s outbox until delivered.

### Multi-device for Bob
Bob's laptop, phone, and tablet all connect to `bob-kith`. The mailbox fans out. Per-device read cursors tracked in the mailbox. No cross-device sync protocol needed; the mailbox is the sync point.

## External chat (the whole story)

Alice wants to chat with Carol, who is in a different tailnet.

1. Alice shares `alice-kith` out to Carol's Tailscale identity using Tailscale's node-sharing feature. Shared nodes are quarantined by default (they can receive connections but cannot initiate arbitrary outbound), which is exactly what we want.
2. Carol shares `carol-kith` out to Alice's identity.
3. Each mailbox's ACL now permits the other's identity. Chat works.

That's it. There is no "invite flow" in the app. There is no admin approval. There is no pending/accepted/revoked state machine. The Tailscale sharing UI is the workflow. The app just reads the current Tailscale ACL state and reflects it.

If Carol doesn't use Tailscale: she can't chat with Alice. That is the product. Don't apologize for it, don't build a gateway, don't add email fallback. The friction is the feature.

## End-to-end encryption

Tailscale already encrypts all overlay traffic with WireGuard. For a v1 where the threat model excludes "root on the mailbox host," that is sufficient: messages on the wire are encrypted; messages at rest on a mailbox are readable by the mailbox's owner (which is the user themselves).

If you want E2EE against "Bob's mailbox host operator" (relevant when Bob rents a VPS): add a per-user signing + encryption keypair generated on first client launch and stored on the client device. The mailbox becomes a dumb ciphertext relay. This is a reasonable v2. For v1 it's overhead without a threat to defend against, because Bob controls his own mailbox host.

Recommendation: ship v1 with TLS-on-overlay only. Add E2EE in v2 when someone asks for it with a real threat model.

## Mailbox protocol (JMAP)

The wire protocol is **JMAP** (RFC 8620 core) with a custom capability for chat. JSON over HTTPS, bound only to the Tailscale interface. Same protocol surface for both owner clients and peer mailboxes; they differ only in which methods they are authorized to call.

JMAP's core envelope, sync semantics (`/changes`), push (EventSource/WebSocket), and method batching with back-references are used as-specified. RFC 8621 (the Mail data type profile) is **not** used; we define a Chat profile instead.

### Capability URI

```
urn:kith:chat:1
```

Clients declare support via the `using` array. The core capability `urn:ietf:params:jmap:core` is always implicit.

### Session object

`GET /.well-known/jmap` returns the Session resource (RFC 8620 §2). Authentication is by Tailscale `whois` on the TCP connection; there is no `Authorization` header.

```json
{
  "capabilities": {
    "urn:ietf:params:jmap:core": {
      "maxSizeUpload": 104857600,
      "maxConcurrentUpload": 4,
      "maxSizeRequest": 10485760,
      "maxConcurrentRequests": 4,
      "maxCallsInRequest": 16,
      "maxObjectsInGet": 500,
      "maxObjectsInSet": 500,
      "collationAlgorithms": ["i;unicode-casemap"]
    },
    "urn:kith:chat:1": {
      "maxBodyBytes": 65536,
      "maxAttachmentBytes": 104857600,
      "supportedBodyTypes": ["text/plain", "text/markdown"]
    }
  },
  "accounts": {
    "a-self": {
      "name": "alice@example.com",
      "isPersonal": true,
      "isReadOnly": false,
      "accountCapabilities": {
        "urn:kith:chat:1": {
          "role": "owner"
        }
      }
    }
  },
  "primaryAccounts": {
    "urn:kith:chat:1": "a-self"
  },
  "username": "alice@example.com",
  "apiUrl": "https://alice-kith.tail-xxxxx.ts.net/jmap/api",
  "downloadUrl": "https://alice-kith.tail-xxxxx.ts.net/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
  "uploadUrl": "https://alice-kith.tail-xxxxx.ts.net/jmap/upload/{accountId}",
  "eventSourceUrl": "https://alice-kith.tail-xxxxx.ts.net/jmap/events?types={types}&closeafter={closeafter}&ping={ping}",
  "state": "s-42"
}
```

The `accountCapabilities.role` field is our extension and is one of `owner` (the connecting peer is the mailbox owner, full access) or `peer` (the connecting peer is a permitted contact, restricted method set). The daemon populates this per-request based on `whois`.

### Data types

All data types inherit JMAP conventions: string ids, opaque to the client; `created`, `updated`, `destroyed` in `/set` responses; `/changes` returns added/updated/destroyed id lists since a state token.

#### `Contact`

A remote identity this mailbox knows about. Populated on first inbound contact (auto-created when a permitted peer first delivers) or manually by the owner.

```
id:              String (server-assigned)
tailscaleUserId: String       // stable id from the Tailscale identity provider
login:           String       // email-shaped login, e.g. "bob@example.com"
mailboxHost:     String       // MagicDNS name, e.g. "bob-kith.tail-yyyyy.ts.net"
displayName:     String|null  // user-editable; falls back to login
firstSeenAt:     UTCDate
lastSeenAt:      UTCDate
blocked:         Boolean
```

#### `Chat`

A conversation. Deterministic id: lowercase hex of SHA-256 of sorted participant `tailscaleUserId`s joined by null bytes. Both sides compute the same id independently, so chats "match up" without negotiation.

```
id:           String
kind:         String         // "direct" | "group"
participants: String[]       // Contact ids; includes self for groups, excludes self for direct
createdAt:    UTCDate
lastMessageAt:UTCDate|null
unreadCount:  Number         // computed server-side from read cursor
```

#### `Message`

```
id:            String                  // ULID, time-sortable
chatId:        String                  // references Chat
senderId:      String                  // Contact id; "self" for outgoing
body:          String                  // UTF-8, bounded by maxBodyBytes
bodyType:      String                  // "text/plain" | "text/markdown"
attachments:   Attachment[]            // embedded; blobIds resolved via downloadUrl
replyTo:       String|null             // Message id
sentAt:        UTCDate                 // sender's clock
receivedAt:    UTCDate                 // this mailbox's clock
deliveryState: String                  // "pending" | "delivered" | "failed" | "received"
deliveredAt:   UTCDate|null
readAt:        UTCDate|null
```

Note: `deliveryState` is `"received"` for incoming messages and one of `pending`/`delivered`/`failed` for outgoing. This asymmetry is intentional: a single table holds both directions and the state field encodes which direction.

#### `Attachment`

Metadata only; bytes live at `downloadUrl`.

```
blobId:      String         // opaque; used in downloadUrl template
filename:    String
contentType: String
size:        Number         // bytes
sha256:      String         // hex
```

### Methods

Owner role can call everything. Peer role can call only the two `Peer/*` methods.

**Owner methods** (standard JMAP shape):

```
Contact/get          Contact/set          Contact/changes      Contact/query
Chat/get             Chat/set             Chat/changes         Chat/query
Message/get          Message/set          Message/changes      Message/query
Message/queryChanges
```

`/query` takes a filter + sort + position/limit and returns an ordered list of ids (RFC 8620 §5.5). `Message/query` supports filter by `chatId`, sort by `sentAt` descending. That's the entire query surface for v1.

`Message/set create` is how the owner's client sends a new message. The daemon:
1. Writes to local `messages` table with `deliveryState=pending`.
2. Returns the created object to the client immediately (optimistic).
3. Enqueues outbox delivery to each recipient mailbox.
4. Emits a state change on the EventSource when `deliveryState` transitions.

**Peer methods** (this is the kithd-to-kithd surface):

```
Peer/deliver
Peer/receipt
```

`Peer/deliver` is how another mailbox hands us a message for our owner. Request shape:

```json
["Peer/deliver", {
  "accountId": "a-self",
  "message": {
    "id": "01HXYZ7K8MQ3V...",
    "chatId": "b3d4...",
    "senderTailscaleUserId": "uid:bob@example.com",
    "body": "hey",
    "bodyType": "text/plain",
    "attachments": [],
    "replyTo": null,
    "sentAt": "2026-04-18T20:14:00Z"
  }
}, "0"]
```

Response:

```json
["Peer/deliver", {
  "accountId": "a-self",
  "accepted": true,
  "receivedAt": "2026-04-18T20:14:00.238Z"
}, "0"]
```

Authorization: the calling peer's `whois` identity must equal `senderTailscaleUserId`. You cannot deliver a message claiming to be from someone else; the transport and the claim must match. This is the whole anti-spoof mechanism.

`Peer/receipt` reports delivery/read state back to the sender:

```json
["Peer/receipt", {
  "accountId": "a-self",
  "messageId": "01HXYZ7K8MQ3V...",
  "kind": "read",
  "at": "2026-04-18T20:20:11Z"
}, "0"]
```

`kind` is `"delivered"` or `"read"`. The sender's mailbox applies this to its own outbound `messages` row.

### Push

EventSource at `eventSourceUrl`. When any state token changes (e.g. new message arrives and the `Message` type's state advances), the daemon emits:

```
event: state
data: {"changed": {"a-self": {"Message": "s-43", "Chat": "s-12"}}}
```

The owner's client then calls `Message/changes` with its last-known state to pull the delta. Standard JMAP push; nothing custom.

Peer mailboxes do not subscribe to EventSource; they push to each other via `Peer/deliver` directly.

### Attachments

Upload: owner client `POST`s binary to `uploadUrl`, receives `{blobId, size, type}`. Client then includes the blob reference in a `Message/set create`.

Peer fetch: when a delivered message references attachments, the recipient mailbox fetches each blob from the sender via `GET {senderDownloadUrl}` (the `downloadUrl` is discoverable because it's in the sender's published Session, which permitted peers can read). Cached locally. Owner clients always fetch from their own mailbox's `downloadUrl`, never cross-mailbox.

This means attachments replicate lazily: the recipient mailbox doesn't pull bytes until the owner's client opens the message. Optional v1.5 optimization: prefetch on delivery for small attachments.

### Authorization summary

One function, called on every request:

```rust
pub async fn authorize(
    req: &Request<Body>,
    ts: &TsLocalClient,
    contacts: &ContactStore,
    self_owner_id: &str,
) -> Result<(Role, Identity), AuthError> {
    let peer = req.extensions().get::<PeerAddr>()
        .ok_or(AuthError::NoPeerAddr)?;
    let who = ts.whois(peer.addr).await?;
    if who.user_profile.id == self_owner_id {
        return Ok((Role::Owner, Identity::from(who.user_profile)));
    }
    if contacts.is_permitted(&who.user_profile.id).await? {
        return Ok((Role::Peer, Identity::from(who.user_profile)));
    }
    Err(AuthError::Unauthorized)
}
```

Owner can call any method. Peer can call `Peer/deliver` and `Peer/receipt` only, and `senderTailscaleUserId` in `Peer/deliver` must equal the caller's identity.

No tokens. No sessions. The Tailscale connection carries identity, JMAP carries semantics. That is the whole protocol.

## Storage

SQLite on the mailbox node. One file. Backup is `cp`. There is one user's data on one mailbox; Postgres is overkill.

Schema:

```sql
-- Identity of this mailbox's owner (cached from Tailscale)
CREATE TABLE self (
  tailscale_user_id TEXT PRIMARY KEY,
  tailscale_login   TEXT NOT NULL,
  display_name      TEXT,
  created_at        INTEGER NOT NULL
);

-- Contacts (other mailbox owners this user has chatted with)
CREATE TABLE contacts (
  peer_user_id      TEXT PRIMARY KEY,
  peer_login        TEXT NOT NULL,
  peer_mailbox_host TEXT NOT NULL,  -- MagicDNS name of their mailbox
  display_name      TEXT,
  first_seen_at     INTEGER NOT NULL,
  last_seen_at      INTEGER NOT NULL,
  blocked           INTEGER NOT NULL DEFAULT 0
);

-- Chats (1:1 for v1; groups come later)
CREATE TABLE chats (
  id                TEXT PRIMARY KEY,  -- deterministic: hash of sorted participant ids
  kind              TEXT NOT NULL,     -- 'direct' | 'group'
  created_at        INTEGER NOT NULL
);

CREATE TABLE chat_members (
  chat_id           TEXT NOT NULL REFERENCES chats(id),
  peer_user_id      TEXT NOT NULL,
  PRIMARY KEY (chat_id, peer_user_id)
);

-- Messages (both sent and received, single table)
CREATE TABLE messages (
  id                TEXT PRIMARY KEY,  -- ULID
  chat_id           TEXT NOT NULL REFERENCES chats(id),
  sender_user_id    TEXT NOT NULL,
  body              TEXT NOT NULL,
  created_at        INTEGER NOT NULL,
  -- Delivery state for outgoing:
  delivery_state    TEXT NOT NULL,     -- 'pending' | 'delivered' | 'failed'
  delivered_at      INTEGER,
  -- Read state:
  read_at           INTEGER,
  -- Reply threading:
  reply_to          TEXT REFERENCES messages(id)
);

CREATE INDEX messages_chat_time ON messages(chat_id, created_at);
CREATE INDEX messages_pending ON messages(delivery_state) WHERE delivery_state = 'pending';

-- Outbox (pending deliveries to peers; retried on backoff)
CREATE TABLE outbox (
  message_id        TEXT PRIMARY KEY REFERENCES messages(id),
  peer_user_id      TEXT NOT NULL,
  peer_mailbox_host TEXT NOT NULL,
  next_attempt_at   INTEGER NOT NULL,
  attempt_count     INTEGER NOT NULL DEFAULT 0,
  last_error        TEXT
);

CREATE INDEX outbox_next ON outbox(next_attempt_at);

-- Attachments (stored as files on disk; this table is metadata)
CREATE TABLE attachments (
  id                TEXT PRIMARY KEY,
  message_id        TEXT REFERENCES messages(id),
  filename          TEXT NOT NULL,
  content_type      TEXT NOT NULL,
  size_bytes        INTEGER NOT NULL,
  sha256            TEXT NOT NULL,
  path              TEXT NOT NULL,     -- on-disk path
  created_at        INTEGER NOT NULL
);
```

## Implementation layout

```
/kith
  /crates
    /kithd                   main daemon binary
    /kithctl                 local CLI (status, list contacts, backup)
    /kith-core               shared types (JMAP envelope, data types, errors)
    /kith-store              SQLite access (sqlx or rusqlite)
    /kith-jmap               JMAP envelope, method dispatch, ResultReference resolver
    /kith-chat               Chat capability: Contact/Chat/Message/Peer methods
    /kith-peer               kithd-to-kithd delivery, outbox retry loop
    /kith-tslocal            Tailscale LocalAPI client (WhoIs, Status over Unix socket)
    /kith-events             EventSource push for owner clients
    /kith-attach             attachment blob storage on disk
  /web                       static client assets (served by kithd)
  /migrations                sqlite migrations
  Cargo.toml                 workspace manifest
  README.md
  architecture.md            (this file)
```

Language: **Rust**. Reasons: consistency with the broader crypto/systems Rust stack (wolfCrypt-DPE, wolfcrypt-ring, rustls-crypto-wolfssl, the Caliptra work); strong fit for JMAP's typed data model (algebraic types + `serde`); no cgo complications when E2EE arrives in v2; single static musl binary cross-compiles cleanly to aarch64 for NAS/Pi deployment.

Suggested crate choices for Phase 1:
- **HTTP:** `axum` (good match for JMAP's handler-per-method shape) with `tokio`.
- **TLS:** `rustls` (and when ready, swap to `rustls-crypto-wolfssl`).
- **JSON:** `serde` + `serde_json`.
- **SQLite:** `rusqlite` with the `bundled` feature (simplifies cross-compile) or `sqlx` if you want async queries. For Phase 1, `rusqlite` behind a small async wrapper is fine; message volume per mailbox is low.
- **IDs:** `ulid` crate for message ids.
- **Unix socket HTTP client (for LocalAPI):** `hyper` + `hyperlocal`, or `reqwest` with Unix socket support.

### Tailscale integration: LocalAPI, not `tsnet`

`kithd` does **not** embed Tailscale. It requires `tailscaled` running on the host and talks to it via the LocalAPI Unix socket (default path `/var/run/tailscale/tailscaled.sock`, or `\\.\pipe\ProtectedPrefix\Administrators\Tailscale\tailscaled` on Windows).

The two LocalAPI calls we actually need:

- `GET /localapi/v0/whois?addr=<ip:port>` — returns the tailnet identity of a peer by their source address. This is the core auth primitive.
- `GET /localapi/v0/status` — returns the current node's identity, the tailnet's other nodes, and the local node's tailnet IPs (which `kithd` binds to for its listener).

That's it for Phase 1. Roughly 150 lines of Rust to wrap these two endpoints as a typed client. Tailscale's LocalAPI is documented and stable in practice, though not under a formal API stability commitment. If it changes, the blast radius is two functions in one crate.

Why not `tsnet`: there is no production-grade Rust equivalent. Tailscale ships a `libtailscale` C library but it is experimental and not recommended for embedding. Shelling out to a Go sidecar would be absurd. The LocalAPI path is standard, boring, and correct.

### The `tailscaled` dependency

`kithd` requires a running `tailscaled` on the same host. This is not a hardship: any machine already participating in the user's tailnet is running `tailscaled` as a matter of course. Deployment becomes:

1. Install Tailscale on the host and log in (`tailscale up`).
2. Install `kithd`.
3. Start `kithd` as a systemd service.

The "single static binary" property is preserved for `kithd` itself. The "embedded Tailscale" property is not, and we judge that not worth a second language in the build.

## Deployment shapes

- **Home server / NAS:** user runs `kithd` as a systemd service or Docker container alongside the existing `tailscaled`. Data persists on their disk.
- **Laptop-only (no always-on mailbox):** mailbox runs on the laptop itself. Messages from offline peers queue on the sender's mailbox until the laptop comes online. Works; not ideal because nobody can reach you when your laptop sleeps. Advertise but discourage.
- **Small VPS:** user rents a $5 VPS, runs `tailscaled` + `kithd`, joins it to their tailnet. Mailbox is always online. Host operator can read data at rest (name this in docs). E2EE in v2 addresses this.
- **Family / small group shared host:** one box, one `tailscaled`, multiple `kithd` instances on different ports, each bound to a different per-user Tailscale identity via Tailscale's "user switching" or separate accounts. Less clean than one-mailbox-per-node; prefer the latter.

## Control plane: Tailscale Inc. vs Headscale

`kithd` is agnostic to which control server the tailnet uses. The client-side binary (`tailscaled`) is identical in either case; only the control server differs. `kithd` only ever talks to `tailscaled` via the LocalAPI, so it doesn't know or care whether the upstream is `controlplane.tailscale.com` or a self-hosted Headscale instance.

### Tailscale Inc. deployment

- **Sharing model:** node sharing is a first-class feature. External chat via "share Alice's mailbox node to Bob's tailnet" works exactly as described in the External Chat section.
- **Identity:** `UserProfile.ID` and `LoginName` are populated from Tailscale Inc.'s SSO integration (Google, Microsoft, etc.), typically email-shaped.
- **DERP:** Tailscale Inc.'s global DERP network. Tailnet Lock available.
- **Trust graph:** Tailscale Inc. operates the coordination plane. They cannot read traffic (WireGuard-encrypted) but they control node admission and DERP relays.

### Headscale deployment

- **Sharing model (same instance):** use Headscale ACLs to grant cross-user access to specific mailbox nodes. Alice and Bob log into the same Headscale server as separate users; a policy entry like the following lets their mailboxes reach each other:

  ```hujson
  {
    "acls": [
      {"action": "accept", "src": ["alice@"], "dst": ["tag:mailbox:443"]},
      {"action": "accept", "src": ["bob@"],   "dst": ["tag:mailbox:443"]}
    ],
    "tagOwners": {
      "tag:mailbox": ["alice@", "bob@"]
    }
  }
  ```

  This is the functional equivalent of Tailscale Inc. node sharing for Option A's purposes.

- **Sharing model (cross-instance):** not supported. Headscale has no federation or instance peering (issues juanfont/headscale#1370 and #588, open since 2023). If Alice runs her own Headscale and Bob runs his own, one of them must join the other's instance. This is a Headscale limitation, not an `kithd` limitation, but it means the "independently self-hosted" story requires a shared Headscale server (family, small group, company).

- **Identity:** `UserProfile.ID` and `LoginName` come from Headscale's user system. Format is simpler than Tailscale Inc.'s — often just a username string without a domain, unless OIDC is configured. **Code must treat `UserProfile.ID` as opaque** and not parse it as email. `DisplayName` and profile picture fields may be empty; fall back to `LoginName` then to the raw id.

- **DERP:** Headscale supports custom DERP maps. Operators can run their own DERP servers or point at a curated non-Tailscale-Inc set. This is the only deployment that closes the "Tailscale Inc. in the trust graph" gap end-to-end.

- **Tailnet Lock:** not available on Headscale at time of writing. Operator control of the Headscale server is the equivalent trust anchor.

- **Version churn:** Headscale's user model has been migrating terminology ("namespaces" → "users") and occasionally changes id formats between versions. Pin a supported Headscale version range in the `kithd` README and integration-test against it.

### Recommendation

For the strongest version of the "tailnet-native, no external trust anchors" story, the canonical deployment is **Headscale + self-hosted DERP + Tailscale client binaries**. Document this configuration as the reference deployment and make sure integration tests cover it. Tailscale Inc. deployment is supported and fine; it just has a larger trust surface.

## Org / multi-user deployments

Organizations running Tailscale (often with OIDC: Google Workspace, Okta, Microsoft Entra, etc.) will ask how Kith accommodates many users. The answer is structural and simple:

**One `kithd` per user, always.** No exceptions, no "multi-tenant mode," no shared process holding many users' data. The daemon name is `kithd` not `kithsd` for a reason: one instance is one person's mailbox, not a directory of mailboxes.

### Why not multi-tenant

If one `kithd` process held data for many users, the project's foundational property ("no central operator, no central plaintext store") would evaporate. Orgs that want multi-tenant chat with admin visibility should use Matrix, Mattermost, Zulip, or Slack. Those products are legitimate and well-maintained and solve the problem Kith is explicitly declining to solve.

### Supported org pattern: shared host, per-user processes

The practical deployment shape for a 200-person company is:

- One or more hosts (VMs, a Kubernetes cluster, whatever the org's ops team prefers).
- One `tailscaled` per host OR one `tailscaled` per user (Tailscale supports both via `TS_STATE_DIR` and `--socket` isolation).
- One `kithd` process per user, bound to that user's Tailscale identity, with its own SQLite database in a per-user data directory.
- A systemd template unit or a supervisor process managing the fleet.

Example systemd template (`/etc/systemd/system/kithd@.service`):

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

Admin provisions a new user with `systemctl enable --now kithd@alice`. Each user's data is siloed in its own SQLite file, owned by its own system user. An IT admin with root on the host can still read any of those files, but there is no SQL query that returns "all messages from all users" — they have to open each database individually. This is a meaningful reduction in blast radius.

### OIDC identity handling

OIDC changes nothing about `kithd`'s code path. `WhoIs` returns whatever the control plane populates, and `kithd` treats `UserProfile.ID` as opaque. Do not parse it, do not assume a format, do not assume it's an email. In practice:

- **Tailscale Inc. + Google Workspace:** `UserProfile.LoginName` is `mark@wolfssl.com`, `UserProfile.ID` is a stable numeric or UUID string.
- **Tailscale Inc. + Microsoft Entra:** same pattern, email-shaped login.
- **Headscale + OIDC (Keycloak, Authentik, Zitadel, etc.):** `LoginName` format depends on Headscale's OIDC config; commonly `username` or `username@domain`. Still opaque to `kithd`.
- **Headscale without OIDC:** bare usernames created via `headscale users create`.

The one place OIDC matters indirectly is contact discovery: when `alice@wolfssl.com` wants to start a chat with `todd@wolfssl.com`, Alice needs to know Todd's mailbox host. For an org, the cleanest answer is to publish an ACL that grants all org members reachability to each other's `tag:kithd` nodes, and let users populate contacts by typing the login name. `kithd` does not need a directory; Tailscale already has one (the tailnet membership list, discoverable via LocalAPI `status`).

### Org sharing pattern via ACL

For an org where everyone should be able to chat with everyone (the normal case), one ACL entry handles it:

```hujson
{
  "tagOwners": {
    "tag:kithd": ["autogroup:member"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["tag:kithd:443"]
    }
  ]
}
```

Every org member's `kithd` carries `tag:kithd`; every org member can reach every other member's mailbox on port 443. No per-user policy editing, no directory service, no admin provisioning step beyond the systemd template unit.

For orgs with stricter compartmentalization (e.g., Finance can't talk to Engineering except through approved channels), write more specific ACLs. Standard Tailscale/Headscale policy machinery applies; `kithd` itself has no opinion.

### What org admins DO NOT get

Named explicitly to avoid confusion:

- **No admin read access** to user messages. Each `kithd`'s database is owned by that user. Root on the host can read anything root can always read; Kith does not provide a legitimate administrative read surface.

## Phases

**Phase 1 (MVP, shippable):**
- Single binary `kithd` (Rust, static musl build).
- Depends on host `tailscaled` via LocalAPI Unix socket.
- 1:1 text chat between two users in the same tailnet.
- JMAP core envelope with ResultReference resolver.
- Chat capability: `Contact/*`, `Chat/*`, `Message/*` owner methods; `Peer/deliver`, `Peer/receipt` peer methods.
- SQLite storage, outbox retry, read receipts.
- EventSource push.
- Minimal web client served by the daemon (uses the same JMAP endpoints).
- `WhoIs`-based auth on every request.

This is small. Ballpark 3000–4000 lines of Rust plus a minimal web client. (Rust is roughly line-count-equivalent to Go for this workload; `serde` removes as much boilerplate as the borrow checker adds.) A coding agent can produce a working version in a single focused session.

**Phase 2:**
- Cross-tailnet via node sharing (test and document the Tailscale sharing flow; no code change needed beyond verifying the peer-identity check accepts shared-in users).
- Attachments.
- Group chats (fanout in the sender's outbox to N recipients; each recipient's mailbox stores independently).
- Native desktop client (Tauri or similar) that connects to the local `kithd`.

**Phase 3 (only if demanded):**
- Per-user E2EE keypair, ciphertext-only mailbox mode.
- Tailnet Lock deployment guide.
- Message search.
- Mobile clients.

**Explicit non-goals, forever:**
- Multi-user `kithd` process. One daemon, one user, always. Kith is not a chat server; there is no tenant model, no admin interface for managing other users' data, no cross-user query surface.
- Federation to non-Tailscale networks.
- Email/SMS bridges.
- Voice/video (different product).
- Central directory service (tailnet membership is the directory).
- Public-internet exposure of any endpoint.

## What makes this Option A and not Option B

- No central service. Losing any one mailbox loses that one user's data, not the network.
- No central operator. There is no single place that holds everyone's messages.
- Identity is Tailscale-native, not app-native.
- External access is a Tailscale primitive (node sharing), not an app feature.
- The app is a thin layer over the overlay. If you deleted the app, the overlay still works; the overlay is the substrate, not a transport.

## Implementation brief for the coding agent

> Build a mailbox daemon in Rust (`axum` + `tokio` + `rusqlite` + `serde`). Each user runs one daemon on a Tailscale node they own. The daemon requires `tailscaled` running on the host and talks to it via the LocalAPI Unix socket (default `/var/run/tailscale/tailscaled.sock`), specifically the `/localapi/v0/whois` endpoint for per-request peer identity and `/localapi/v0/status` for the local node's tailnet IPs. `kithd` binds its HTTPS listener only to the tailnet IPs returned by `status`; it must not listen on any public interface.
>
> The daemon exposes a JMAP API (RFC 8620 core) with a custom `urn:kith:chat:1` capability defining `Contact`, `Chat`, `Message`, and `Attachment` data types and methods. Standard JMAP conventions: `/get`, `/set`, `/changes`, `/query` shape; ResultReferences for batching (implement per RFC 8620 §3.7); EventSource for push. Two peer methods `Peer/deliver` and `Peer/receipt` handle kithd-to-kithd message exchange with the same envelope and same authorization mechanism.
>
> Authentication on every request: extract the peer socket address, call `WhoIs` on the LocalAPI, classify the caller as `Owner` (identity matches mailbox owner from config) or `Peer` (identity is in the contacts table), restrict method access accordingly, reject otherwise. The `senderTailscaleUserId` field in `Peer/deliver` must equal the caller's verified identity (anti-spoof, structural, no signing needed).
>
> Storage is SQLite via `rusqlite` with the `bundled` feature. Outgoing messages to peer mailboxes that are unreachable are queued in an outbox table and retried with exponential backoff via `Peer/deliver` calls to the recipient's JMAP API URL (discovered from the contact's mailbox host). Chat ids are deterministic: `chatId = hex(sha256(sorted_participant_tailscale_user_ids.join("\x00")))`, so both sides derive the same id without negotiation.
>
> Ship a minimal web client served by the daemon at `/` that speaks JMAP to its own mailbox. Plain HTML + a small amount of JavaScript is fine; no SPA framework required for Phase 1.
>
> Do not implement: embedded Tailscale (`tsnet` has no Rust equivalent, talk to `tailscaled` instead); central services; OAuth; JWTs; sessions; RFC 8621 Mail data types; MIME; E2EE; federation; public-internet endpoints; peer-to-peer NAT traversal (Tailscale handles transport).
>
> Cross-tailnet chat works via Tailscale's node-sharing feature with no app-level changes beyond verifying that shared-in peer identities are accepted by the contacts-permission check.

The whole design fits on one page because the design is small. That is the point.
