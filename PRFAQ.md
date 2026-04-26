# Kith — PR/FAQ

---

## Press Release

**FOR IMMEDIATE RELEASE**

**Seattle, WA — April 18, 2026**

### Kith Puts Chat Back in Your Hands: Tailnet-Native Messaging With No Central Server

*Each user runs their own mailbox. Tailscale is the network. There is nothing in the middle.*

**Seattle, WA** — Kith, an open-source messaging system built for people who already run their own infrastructure, is available today. Kith gives every participant a mailbox daemon they run on hardware they control, wires mailboxes together over a Tailscale overlay network, and uses Tailscale's cryptographic identity as the only authentication layer. There is no Kith account, no Kith server, and no Kith company holding your messages.

The core insight behind Kith is that a significant class of users — systems administrators, homelab operators, small engineering teams, privacy-conscious individuals — already have the infrastructure and already use Tailscale. For these users, a self-hosted chat system does not need to invent an identity system, a transport layer, or a trust model. Tailscale provides all three. Kith threads those primitives into a mailbox protocol and gets out of the way.

Each user runs `kithd`, a small daemon on any Tailscale node they own — a home server, a NAS, a five-dollar VPS. The daemon stores messages in a single SQLite file and speaks JMAP over the tailnet. Clients — a minimal web UI and a terminal UI in the initial release — connect only to their owner's mailbox, never directly to any other user's mailbox. Mailboxes talk to mailboxes. Authentication is Tailscale's `WhoIs` API called on every request: no passwords, no sessions, no tokens. Phase 1 is 1:1 chat within a single tailnet. Cross-tailnet chat via Tailscale's node-sharing feature, with no in-app invite flow, is the Phase 2 target.

"I've run my own email since 2009 and my own XMPP server since 2014," said a systems administrator and homelab operator who tested an early build. "Both of those are enormous maintenance surfaces. Kith is the first messaging system where I looked at the architecture and thought: yes, I understand every piece of this, I trust every piece of this, and none of it will break in a way I can't debug at 2am."

"The tailnet *is* the network," said the Kith developer. "We did not build a messaging system and then try to secure it. We built on top of a network that is already authenticated, already encrypted, already scoped to exactly the people you want. The design decisions that look like constraints — no central server, no external users without Tailscale, no multi-tenant mode — are the point. Every one of them is load-bearing."

Kith is available today as source code under the AGPL-3.0-or-later license. Build instructions are in the repository. There are no binary releases, no hosted version, and no sign-up. If you run Tailscale and you want to build and operate your own chat infrastructure, Kith is for you.

---

*Kith (Old English `cȳþþ`) means one's friends and acquaintances — those admitted to your circle. It is the "kith" in "kith and kin."*

---

## FAQ

### Customer FAQ

---

**Do I need to run a server?**

Yes. Each Kith participant runs `kithd`, the mailbox daemon, on a Tailscale node they own and operate. This is not a limitation that will be relaxed in a future release — it is the design. Kith is for people who are already running their own infrastructure or are willing to start. A low-end VPS ($5/month range) is sufficient; a home server or NAS works equally well. If you want messaging that requires no infrastructure of your own, Kith is not the right tool. Signal, iMessage, or WhatsApp are.

---

**Does everyone I want to chat with need Tailscale?**

Yes. Tailscale is the transport, the identity layer, and the access control system. There is no fallback path over the public internet, no email bridge, no SMS gateway. If the person you want to chat with does not use Tailscale and is not willing to install it, they cannot use Kith. This is intentional. The friction of requiring Tailscale filters for users who are already operating in a trust model compatible with Kith's.

---

**Can I chat with people in a different Tailscale tailnet?**

Yes, in Phase 2 and beyond, using Tailscale's node-sharing feature. Alice shares her `alice-kith` node to Carol's Tailscale identity; Carol shares `carol-kith` back to Alice. Both mailboxes then appear on each other's tailnet and can deliver messages directly. There is no in-app invite flow, no pending/accepted state machine inside Kith. The Tailscale admin UI is the workflow.

Note: this requires both parties to be on Tailscale's coordination plane, or both to be on the same Headscale instance. Cross-instance federation between two separate Headscale deployments is not currently supported by Tailscale's node-sharing model, and Kith inherits that limitation.

---

**What if the person I want to chat with doesn't use Tailscale?**

They cannot use Kith. There is no workaround, no guest mode, no web link to share. The requirement is the feature: by restricting participation to people with Tailscale identities, Kith eliminates an entire class of access control problems. The moment you add an unauthenticated external access path, you need spam filtering, invite expiry, rate limiting, and abuse reporting. None of that exists in Kith because none of it is needed.

---

**What happens when I'm offline?**

Your mailbox continues running on your server. Messages sent to you are delivered to your `kithd` and stored there. When you reconnect your client, your client pulls from your mailbox. The mailbox is the store; the client is ephemeral. This is the same model as IMAP email, and it is why the thing running on your server is called a mailbox.

---

**What happens if my mailbox goes offline?**

Delivery from your peers to you will fail until your mailbox comes back. Senders will get a delivery error; their `kithd` may retry depending on configuration. This is a known tradeoff of not having a central relay with guaranteed uptime. If you need high availability, run your mailbox on infrastructure with an uptime commitment (a VPS with SLA, for example) rather than a home server that loses power during storms. Kith does not hide this tradeoff.

---

**Can I use multiple devices?**

Yes. Multiple clients can connect to the same `kithd` simultaneously. Because auth is Tailscale identity on the connection, any device on your tailnet can reach your mailbox as owner. There is one mailbox, one message store, and many possible client connections to it. You do not need to configure multi-device sync — it is a consequence of the architecture.

---

**Who can read my messages?**

On your mailbox: anyone with root access to the host can read the SQLite file. In v1, messages at rest on the mailbox host are not encrypted beyond filesystem permissions. This is the explicit threat-model boundary for v1 — root on the mailbox host is out of scope. If you are on a shared VPS, the hosting provider can read your data at rest. Per-user E2EE is planned for v2 and would address this.

In transit: all traffic between mailboxes travels over WireGuard through the Tailscale overlay. When a direct path between nodes is not available, Tailscale routes through DERP relays operated by Tailscale Inc. (or your own DERP servers if you run Headscale). DERP sees WireGuard ciphertext only, not plaintext. The dependency on Tailscale Inc.'s infrastructure exists; we are not obscuring it.

---

**Is this end-to-end encrypted?**

In v1: not in the cryptographic sense. Transit is WireGuard-encrypted, but the mailbox stores plaintext. Anyone with access to the mailbox host can read the SQLite file. "End-to-end" in the strongest sense — where even the server operator cannot read messages — requires per-user key management, and that is a v2 goal. We chose to be honest about this rather than call WireGuard transit encryption "E2EE."

---

**What does my hosting provider / VPS operator see?**

In v1: if they have root on the machine, they can read the SQLite file and see your messages in plaintext. The same is true of the OS, disk images, and any snapshots. This is the same threat model as self-hosted email or self-hosted XMPP. It is not a regression from those systems; it is parity. Running on hardware you physically control (home server, NAS) eliminates this exposure. The v2 E2EE work is specifically motivated by users who must or prefer to run on VPS infrastructure.

---

**Can my employer read my messages?**

If your employer operates the Tailscale ACLs for your tailnet and controls the machine running `kithd`, yes. This is the same answer as self-hosted email at an organization: the operator controls the infrastructure. Kith does not add a layer of protection against the infrastructure operator. If you need messaging that your employer cannot access even in principle, run `kithd` on personal hardware outside your employer's tailnet.

---

**What's the backup story?**

`cp kith.db kith.db.bak`. That is the entire backup story. SQLite is a single file. Standard backup tools — rsync, restic, Backblaze B2, anything — work without modification. There is no backup agent, no backup format, no export wizard. This is one of the practical benefits of choosing SQLite as the store.

---

**Is there a mobile app?**

Not in v1. The initial release ships a minimal web client that works in a mobile browser over your tailnet. A native mobile client would require Tailscale on the mobile device (which exists) and either a native `kithd` client or a mobile-accessible web UI. Mobile is a Phase 3 item, contingent on demand. The web UI is usable on mobile as a stopgap.

---

### Internal FAQ

---

**Why not Matrix/Element?**

Matrix is a federated protocol designed for interoperability across organizational and trust boundaries, with a homeserver model that assumes mutual distrust between servers. It is a remarkable piece of engineering for that use case. It is also operationally heavy: a production Matrix homeserver involves Postgres, Synapse (or Dendrite), a reverse proxy, certificate management, and ongoing schema migrations. The federation model introduces complexity — state resolution, room DAGs, partial joins — that exists because Matrix must handle adversarial federation.

Kith's target users already have a shared trust model enforced by Tailscale ACLs. They do not need federation to arbitrary external servers; they need reliable 1:1 and small-group messaging within a controlled network. Kith trades Matrix's generality for a radically simpler operational profile. The comparison is not "which is better" — it is "which is appropriate for this specific use case and operator profile."

---

**Why not Signal?**

Signal requires a phone number, relies on Signal's central servers for identity and message routing, and does not have a self-hosted mode. Its security model is excellent for its intended use case — consumer messaging across organizational boundaries. But it is a hosted service with a dependency on Signal Foundation's infrastructure, and it cannot be operated independently. Kith is precisely the thing Signal is not: self-hosted, infrastructure-you-control, no dependency on a third-party service's continued operation. These are different products for different requirements.

---

**Why not build on top of XMPP?**

XMPP (Extensible Messaging and Presence Protocol) is a viable base layer and is genuinely underrated. The reason we did not use it is the extension ecosystem. XMPP's core is simple; the features users expect (multi-device sync, read receipts, message correction, file transfer) live in a sprawling and inconsistently implemented XEP landscape. Interoperability between XMPP servers in practice is worse than the spec suggests, because XEP support varies. We would have been building on a protocol whose extension model is the primary source of complexity, not the core.

JMAP (RFC 8620) is a modern HTTP/JSON protocol with a clean batching and push model, and it maps naturally to the mailbox metaphor. Writing a custom JMAP capability (`urn:ietf:params:jmap:chat`) gives us the protocol primitives we need — request batching, push via EventSource, ResultReferences — without inheriting XMPP's extension fragmentation.

---

**Why JMAP and not a simpler custom protocol?**

The temptation to write a simple custom protocol is real, and we thought about it. The problem with custom protocols is that they tend to be simple at the start and accrete complexity as features are added, without ever developing the principled structure that makes complexity manageable. JMAP gives us: a proven request/response and push model, ResultReferences for batched dependent calls, a defined error taxonomy, and an existing client library ecosystem. The custom part — `urn:ietf:params:jmap:chat` — is only the part that needs to be custom. The transport, batching, and push semantics are already specified and tested by the JMAP email world.

The tradeoff is that JMAP is more complex to implement than a naive REST API. We believe that complexity is front-loaded into the initial implementation and pays down over the life of the project, whereas a naive REST API's complexity is back-loaded into every feature addition.

---

**Why Rust?**

Several reasons compound. First, `kithd` is a long-running daemon on user-owned hardware. Memory safety is important: a memory-safety bug in a daemon is an exploitable vulnerability in infrastructure users are trusting. Second, the target deployment profile includes low-resource hardware (small VPS, NAS, home servers) where the performance and memory footprint of a Rust binary is materially better than a Go or JVM service. Third, producing a static musl binary for Phase 1 simplifies deployment significantly — single binary, no runtime dependency, systemd unit, done. Fourth, the SQLite, Tailscale LocalAPI, and JMAP library ecosystems in Rust are adequate for this purpose.

We are not claiming Rust is always the right choice. It has a steeper learning curve and longer compile times. For a project where the primary operator concern is long-term stability, low resource use, and security on constrained hardware, the tradeoffs favor Rust.

---

**Why SQLite and not Postgres?**

Multi-tenant systems need Postgres because multiple users' data needs to be isolated, backed up independently, and scaled horizontally. Kith is explicitly single-tenant: one `kithd` per user, always. Given that constraint, SQLite is strictly superior for this use case. It is a single file, backed up with `cp`, requires no separate service process, handles the write concurrency of a single-user mailbox easily, and is well-supported by WAL mode for concurrent reads. Postgres would add an operational dependency — a running Postgres service, a connection pool, migrations against a live database — with no benefit for a single-tenant workload. We chose the simpler tool that is correct for the problem.

---

**Why not embed Tailscale (tsnet/libtailscale)?**

`tsnet` allows embedding a Tailscale node directly in a Go application, handling its own network identity without depending on a system `tailscaled`. It is appealing because it reduces the operational dependency graph. We chose not to use it for two reasons.

First, `kithd` is written in Rust, and `tsnet` is a Go library. Bridging via `libtailscale` is possible but adds FFI complexity and a cgo dependency that conflicts with the goal of a static musl binary.

Second, and more importantly, Kith is designed to sit alongside `tailscaled` on a node that the user already operates as a Tailscale node. The user's ACLs, DNS, exit node configuration, and peer list are all managed through the existing `tailscaled`. Embedding a separate Tailscale node would create a second identity on the same machine with its own ACL surface, which is harder to reason about from a security standpoint. Using the LocalAPI of the host's `tailscaled` is simpler and keeps the trust model clean.

---

**Why no multi-tenant mode? (And why is this principled, not just "it's hard")**

Multi-tenancy is not missing because it was too hard to implement. It is absent because multi-tenancy changes the threat model in ways that undermine Kith's core value proposition.

In a multi-tenant deployment, a single `kithd` process would handle messages for many users. This means one operator has access to all users' messages. Kith's current threat model states explicitly that root on the mailbox host is out of scope — because in a single-tenant deployment, the person with root on the host is the user, or someone the user has explicitly granted that trust. In a multi-tenant deployment, the operator is a distinct party from the user, and the operator can read all messages. This is the exact threat model Kith is designed to avoid.

Adding multi-tenant mode would require per-user E2EE (a v2 goal for the single-tenant case too), key management, and a data isolation model that does not currently exist. More fundamentally, a multi-tenant Kith would be a different product with a different threat model, not an enhancement to this one. Organizations that need multi-user infrastructure managed by an operator have Matrix, Mattermost, and Zulip, all of which are designed for that model. Kith is designed for the case where the user is the operator.

---

**What's the business model?**

There is no business model. Kith is an open-source project, AGPL licensed, built because the right tool did not exist. The developer is not building a company around it.

If Kith becomes widely used and someone wants to build a managed hosting offering, the AGPL requires them to publish their changes but does not prohibit the business. The developer may or may not participate in that. The project is designed to be operable without the developer's involvement — that is what open source is for.

---

**Why is external chat a Tailscale UI action and not an in-app invite?**

Because every in-app invite flow is a trust and lifecycle management system in disguise, and building that system correctly is a large project that has nothing to do with messaging.

An in-app invite requires: generating an invite token, storing pending invites, expiring them, handling acceptance or rejection, revoking access when the relationship ends, and displaying the state of all pending and accepted invites to both parties. Each of those steps is a UI surface, a database schema, and an attack surface.

Tailscale node sharing already solves this problem. It has a UI, a notification flow, an acceptance model, and a revocation mechanism. When Alice shares her node to Carol's identity, Carol gets a notification, accepts, and the node appears on Carol's tailnet. When Alice revokes the share, access ends immediately, enforced by the network layer. Kith does not need to replicate this.

Using Tailscale's UI as the external-access workflow means the trust relationship is expressed at the network level, not in application state. This is both simpler and more robust: access control happens before a TCP connection is even established, rather than inside the application after the connection. The constraint that "external chat requires a Tailscale admin action" is not a missing feature — it is Kith correctly identifying which layer of the stack should own access control.

---

> **What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
