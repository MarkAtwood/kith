# Kith: Architecture and Data Handling Statement

This document describes the architecture of kith as it relates to data
handling, operator responsibilities, and lawful data access requests.
It is a factual description of the software's design, not legal advice.

## What kith is

Kith is open-source peer-to-peer chat software. Each user runs their own
instance (`kithd`) on their own device. Messages are transmitted directly
between participants' devices and stored locally on each participant's
device. There is no central server, relay, or intermediary that stores
or forwards message content.

Kith is software, not a service.

## What the author operates

The author of kith publishes source code under the AGPL-3.0-or-later
license. The author does not operate:

- A chat service or communications platform
- A server that stores, relays, or forwards messages for other users
- A discovery service or user directory
- An account registration system
- A telemetry, analytics, or logging service
- A key server, certificate authority, or identity provider

The author may run a personal `kithd` instance for their own use.
That instance contains only the author's own messages, the same as
any other user's instance.

## Where data is stored

All message content, attachments, contact lists, and chat metadata are
stored locally on each user's device, in a SQLite database and a local
blob directory managed by that user's `kithd` instance. There is no
cloud storage, no server-side database, and no backup service operated
by the author or the project.

When a message is sent, it is transmitted directly from the sender's
device to the recipient's device over an encrypted peer-to-peer
connection. After delivery, the message exists on the sender's device
and the recipient's device. No third party receives or stores a copy.

## What the author can produce in response to a data access request

- **Source code**: publicly available under AGPL-3.0-or-later.
- **The author's own messages**: stored on the author's own device, like any other user.

The author cannot produce:

- Any other user's messages, contacts, or metadata.
- Network traffic logs, connection records, or routing metadata.
- Encryption keys belonging to other users.
- Any data from any other user's device.

This is not a policy choice. It is a technical impossibility arising
from the architecture. The author does not have access to other users'
data because no component of the system transmits that data to the
author or to any infrastructure the author controls.

## Architecture invariants

The following properties are architectural invariants maintained by
design. Changes that would violate these invariants would fundamentally
alter the system's data handling characteristics.

1. **No relay**: Messages are transmitted peer-to-peer. No server
   operated by the author or the project stores or forwards messages
   on behalf of users.

2. **No centralized discovery**: Peer discovery is performed by the
   transport layer (e.g., Tailscale's network, DNS records, mDNS).
   The author does not operate a discovery service.

3. **No account database**: User identity is provided by the transport
   layer (e.g., Tailscale identity, TLS certificates, TOFU key
   pinning). The author does not maintain a registry of users.

4. **No telemetry**: The software does not transmit usage data,
   diagnostics, crash reports, or any other information to the author
   or to any third party.

5. **No key escrow**: Encryption keys are generated and stored locally
   on each user's device. The author has no access to any user's keys.

## Third-party infrastructure

Kith's default transport uses Tailscale, a third-party overlay network.
Tailscale's infrastructure handles network-layer routing and may retain
connection metadata (IP addresses, connection timestamps, peer
relationships) subject to Tailscale's own privacy policy and legal
obligations. The author of kith has no access to Tailscale's
infrastructure or logs.

Alternative transports (DNS-based discovery, mDNS, onion services) use
their respective infrastructure with their respective data handling
properties.

## Verifiability

Kith is licensed under AGPL-3.0-or-later. The complete source code is
available for inspection. Any party can verify the claims in this
document by reading the source code and confirming that no component
transmits user data to the author or to any centralized infrastructure.

---

*This document describes the architecture of kith as of the date of its
last commit. It is a factual technical description, not a legal opinion,
privacy policy, or terms of service.*
