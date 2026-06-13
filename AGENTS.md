# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var
## Project Context

Kith is a **tailnet-native chat daemon** (`kithd`). One daemon per user, running on a Tailscale node the user owns. No central service. No multi-tenant mode.

Read `kith-architecture.md` before making protocol or schema changes — the design doc is the authoritative spec.

## Before Writing Code

For any task touching more than 3 files or requiring more than a few steps:
1. File a Beads epic and break it into issues
2. Write a plan and get approval before touching code
3. Work through issues one at a time, using parallel subagents within each issue

## Crate Boundaries

| Crate | What belongs here |
|---|---|
| `kith-core` | Shared types, error types, JMAP envelope structs |
| `kith-store` | All SQLite access — no SQL in other crates |
| `kith-jmap` | Method dispatch, ResultReference resolver, JMAP envelope parsing |
| `kith-chat` | Chat capability methods (Contact/Chat/Message/Peer) |
| `kith-peer` | Outbound delivery to peer mailboxes, outbox retry loop |
| `kith-tslocal` | Tailscale LocalAPI client: `WhoIs` and `Status` only |
| `kithd` | Axum router, TLS listener setup, startup, signal handling |

**No SQL outside `kith-store`. No Tailscale API calls outside `kith-tslocal`. No `unsafe`.**

## Authorization is Structural

Auth happens in one place: `kith-tslocal`'s `authorize()` function, called on every request. Do not add auth checks inline elsewhere. If a method needs different authorization, add a role check at the dispatch level in `kith-jmap`, not scattered through method implementations.

## Protocol Invariants

Never violate these without explicit approval:
- `senderUserId` in `Peer/deliver` must equal the caller's verified `WhoIs` identity
- Chat IDs are `hex(sha256(sorted_user_ids.join("\x00")))` — deterministic, both sides agree
- Message IDs are ULIDs — time-sortable, no coordination
- Listener binds ONLY to tailnet IPs from `/localapi/v0/status`

## Test Integrity

**Never cheat on tests.** No exceptions.

- Failing test → fix the code, not the test
- Never hardcode a value derived from running the code under test
- Never mock a store/network call just to make the test green — integration tests against real SQLite are preferred
- If a fix is out of scope, escalate rather than papering over it

**Every test needs an independent oracle.** Kith-specific examples of what is NOT acceptable:
- Send a JMAP `Message/set create`, then call `Message/get` on the same in-process state and assert the same value came back — that's the code verifying itself
- Stub `WhoIs` to return "owner" and assert the owner got through — that test can't catch a logic error in the role check
- Deliver a message via `Peer/deliver`, read it back from the same code path, declare success

Acceptable oracles: manually constructed JMAP request/response pairs from the RFC spec, a separate Python/curl script hitting the running daemon, or hardcoded reference values computed offline.

**Auth rejection must be tested.** For every authorized path, there must be a test that the wrong identity is rejected. For `Peer/deliver`, test that a mismatched `senderUserId` is rejected before any write.

## Defensive Input Handling

Kith's trust boundary: **only the Tailscale peer identity from `WhoIs` is trusted.** Everything else arriving from the network is attacker-controlled.

When writing any code that handles JMAP requests or peer messages:
- Enforce size limits (`maxBodyBytes`, `maxAttachmentBytes`) at parse time, before any storage or processing
- Sanitize attachment `filename` for path traversal (`../`, absolute paths, null bytes)
- Validate `content_type` parses as legal MIME before storing
- Validate all referenced IDs (`chatId`, `replyTo`, `blobId`) exist and belong to the right account/chat before any write
- Recompute `chatId` from participants on `Peer/deliver` and reject if it doesn't match the supplied value
- Compare `senderUserId` against `WhoIs` result **before** any database write
- Use `receivedAt` (local clock) for message ordering; treat peer-supplied `sentAt` as display-only
- Validate `blobId` format before constructing any file system path from it

If in doubt: reject with an error, log the reason, do not silently accept partial data.

## Quality Gate (run before every commit)

```bash
cargo fmt --all
cargo clippy --all-features -- -D warnings
cargo test
```

All three must pass clean. If `cargo fmt` changes files, stage and include those changes in the commit.

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

**Beads is the only task and planning tool.** Do NOT use:
- TodoWrite / markdown TODO lists
- Scratchpad or audit files (`audit-*.md`, `plan-scratch.md`, or any similar throwaway planning file)
- MEMORY.md or any other markdown file as a knowledge store

The only permitted markdown planning artifact is a crate's `PLAN.md`, which is a permanent
design document checked into the repo — not a scratchpad. Use `bd remember` for persistent
knowledge and `bd create` for all task tracking.
