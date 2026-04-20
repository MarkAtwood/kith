# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->


## What This Is

**Kith** — tailnet-native chat. Mailboxes among kith.

Each user runs one `kithd` instance on a Tailscale node they own — their personal mailbox. There is no central server, no central operator, no shared service tier. Tailscale identity is user identity. Mailboxes talk to mailboxes over the Tailscale overlay.

**One daemon, one user, always.** There is no multi-tenant mode and there never will be.

License: AGPL-3.0-or-later (`kithd` is a network service; AGPL §13 applies).

## Build & Test

```bash
# Build the workspace
cargo build

# Run all tests
cargo test

# Run kithd integration tests (harness, delivery, retry)
cargo test -p kithd --features test-utils

# Test a specific crate
cargo test -p kith-jmap

# Format (required before every commit)
cargo fmt --all

# Lint (all warnings are errors)
cargo clippy --all-features -- -D warnings

# Cross-compile static musl binary (deployment target)
# Requires: cargo install cargo-zigbuild  (and zig on PATH)
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl   # NAS / Pi
```

## Architecture Overview

```
/crates
  /kithd          main daemon binary
  /kithctl        local CLI (status, list contacts, backup)
  /kith-core      shared types: JMAP envelope, data types, errors
  /kith-store     SQLite access layer (rusqlite)
  /kith-jmap      JMAP envelope, method dispatch, ResultReference resolver
  /kith-chat      Chat capability: Contact/Chat/Message owner methods
  /kith-peer      kithd-to-kithd delivery, outbox retry loop
  /kith-tslocal   Tailscale LocalAPI client (WhoIs + Status over Unix socket)
  /kith-events    EventSource push for owner clients
  /kith-attach    attachment blob storage on disk
/web              static client assets (served by kithd at /)
/migrations       SQLite migration files
Cargo.toml        workspace manifest
kith-architecture.md  full design doc — read this before making protocol changes
```

**Key dependencies:**
- `axum` + `tokio` — async HTTP server (good match for JMAP's per-method handler shape)
- `rusqlite` with `bundled` feature — SQLite (simplifies musl cross-compile)
- `serde` + `serde_json` — JMAP JSON handling
- `rustls` — TLS (swap to `rustls-crypto-wolfssl` when ready)
- `ulid` — time-sortable message IDs

## Tailscale Integration

`kithd` does **not** embed Tailscale. It requires `tailscaled` running on the same host and talks to it via the LocalAPI Unix socket (default: `/var/run/tailscale/tailscaled.sock`).

Two LocalAPI calls only:
- `GET /localapi/v0/whois?addr=<ip:port>` — per-request peer identity (the core auth primitive)
- `GET /localapi/v0/status` — local node identity and tailnet IPs (used for binding the listener)

**`kithd` binds its HTTPS listener ONLY to tailnet IPs returned by `/status`. Never on any public interface.**

## Authorization Model

On every request: extract peer socket address → call `WhoIs` on LocalAPI → classify caller:

| Result | Access |
|---|---|
| Identity matches `self_owner_id` | **Owner** — all methods |
| Identity is in `contacts` table | **Peer** — `Peer/deliver` and `Peer/receipt` only |
| Anyone else | 401 |

`Peer/deliver` requires that `senderTailscaleUserId` in the request body equals the caller's verified `WhoIs` identity. The Tailscale transport proves the claim; no signing or tokens needed.

## Wire Protocol

JMAP (RFC 8620 core) with custom capability `urn:kith:chat:1`. JSON over HTTPS, listener bound to tailnet interface only.

**Owner methods:** `Contact/{get,set,changes,query}`, `Chat/{get,set,changes,query}`, `Message/{get,set,changes,query,queryChanges}`

**Peer methods:** `Peer/deliver`, `Peer/receipt`

**Push:** EventSource at `/jmap/events`. On state advance the daemon emits `event: state` with changed type→state map. Client calls `Message/changes` (or `Chat/changes`) to pull the delta.

**Chat IDs** are deterministic: `hex(sha256(sorted_tailscale_user_ids joined by \x00))`. Both sides compute the same ID without negotiation.

## Storage

SQLite via `rusqlite` (`bundled` feature). One file per user. Tables: `self`, `contacts`, `chats`, `chat_members`, `messages`, `outbox`, `attachments`.

Outbox retry uses exponential backoff; outbox rows are indexed by `next_attempt_at`. Message IDs are ULIDs (time-sortable, no coordination).

## Conventions & Patterns

- **`UserProfile.ID` is opaque** — never parse it as email or assume a format. It is a stable key that differs between Tailscale Inc. deployments (numeric/UUID) and Headscale (varies by OIDC config). Store and compare; do not interpret.
- **No `unsafe`** — this codebase has no FFI. If you think you need `unsafe`, stop and ask.
- **Error types live in `kith-core`** — all other crates import from there.
- **Cargo features must be additive** — never enable behavior unconditionally in `Cargo.toml`.
- **No central anything** — no shared process, no admin query surface, no cross-user data access.
- **`UserProfile.DisplayName` may be empty** on Headscale without OIDC — always fall back to `LoginName`, then to raw ID.

## Test Integrity

**Never cheat on tests.** This is a hard rule with no exceptions.

- Never modify, skip, weaken, or delete a failing test to make it pass. Fix the code.
- Never hardcode expected values derived from running the code under test.
- Never mock a result to make a test green — a mocked test that passes proves the mock works, not the code.
- If the code cannot be fixed within scope, stop and escalate. Do not paper over it.

**Every test must have an independent oracle.** A test that sends a JMAP request and checks that the response matches what the same code just produced proves nothing. Acceptable oracles:
- Known-good JMAP request/response pairs constructed manually from the RFC spec
- A second independent implementation (e.g., a Python script exercising the same endpoint)
- Bit-exact comparison against a reference value computed offline and hardcoded

Integration tests that hit a real SQLite file are preferred over unit tests that mock the store — we got the store layer wrong in isolation before and the integration test caught it.

**Auth tests must not self-certify.** A test that checks authorization by calling the endpoint as the owner, using the same `WhoIs` stub that returns "owner", and asserting "owner got in" proves nothing. Tests must cover the rejection path (wrong identity, non-permitted peer, mismatched `senderTailscaleUserId`) using an independent fixture, not a circular dependency on the code under test.

## Defensive Input Handling

**Trust boundaries in Kith:**

| Source | What to trust | What not to trust |
|---|---|---|
| Tailscale TCP peer address | The address is real (Tailscale guarantees it) | Nothing else |
| `WhoIs` result for that address | `UserProfile.ID` and `LoginName` are the verified identity | Nothing about message content |
| JMAP request body (owner) | The caller's identity (from WhoIs) | Every field value in the request |
| JMAP request body (peer) | The caller's identity (from WhoIs) | All field values, especially `senderTailscaleUserId` |
| Peer `body` text | Nothing | May be oversized, malformed UTF-8, or injection attempts |
| Peer attachment metadata | Nothing | `filename`, `content_type`, `size` are all attacker-controlled |
| Peer `sentAt` timestamp | Nothing — use `receivedAt` (local clock) for ordering | Sender clock is unverified |
| `chatId` in `Peer/deliver` | Nothing — recompute from participants and compare | Peer-supplied value may be wrong or malicious |
| `replyTo` in any message | Nothing — validate the referenced ID exists before storing | May reference nonexistent or cross-chat messages |

**Validate at every boundary:**
- Enforce `maxBodyBytes` and `maxAttachmentBytes` limits at parse time, before any storage
- Sanitize attachment `filename` (path traversal: `../`, absolute paths, null bytes)
- Reject `content_type` values that don't parse as valid MIME
- Validate `blobId` format before using it in file system paths
- Clamp or reject `size` claims in attachment metadata — verify against actual bytes received
- Reject JMAP calls that reference IDs in the wrong account or wrong chat
- `senderTailscaleUserId` in `Peer/deliver` must be compared against WhoIs result **before** any database write

**Rust-specific:** use `str::from_utf8` (or serde's built-in UTF-8 validation) explicitly for any bytes arriving from the network before treating them as strings. Do not assume `body` is valid UTF-8 just because the field type says `String`.

## Quality Gates

Run before every commit:

```bash
cargo fmt --all                           # commit any formatting changes this produces
cargo clippy --all-features -- -D warnings
cargo test
```

If touching cross-compile targets:

```bash
# Requires: cargo install cargo-zigbuild  (and zig on PATH)
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

## Design Constraints (permanent non-goals)

These are load-bearing product decisions. Do not route around them:

- **No multi-tenant `kithd`** — one daemon, one user, always.
- **No admin read access to messages** — each user's SQLite file is their own.
- **No E2EE in Phase 1** — planned for v2. Current threat model (user controls their own mailbox host) does not require it.
- **No embedded Tailscale** — `tsnet` has no Rust equivalent. Talk to `tailscaled` via LocalAPI.
- **No public-internet endpoints** — listener is tailnet-only.
- **No JWTs, OAuth, or sessions** — Tailscale identity on the TCP connection is the only auth.
- **No federation to non-Tailscale networks** — the friction is the feature.

## Phase 1 Scope

MVP: 1:1 text chat between two users in the same tailnet. Single static musl binary. Minimal web client served by the daemon. Target: ~3000–4000 lines of Rust plus a small web client.

Phase 2: cross-tailnet via node sharing, attachments, group chat, native desktop client.
Phase 3 (only if demanded): per-user E2EE, message search, mobile clients.
