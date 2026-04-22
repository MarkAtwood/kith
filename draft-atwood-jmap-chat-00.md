---
title: JMAP for Chat
abbrev: JMAP Chat
docname: draft-atwood-jmap-chat-00
category: info
stream: independent

ipr: trust200902

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
  -
    fullname: Mark Atwood
    email: mark@reviewcommit.com

normative:
  RFC2119:
  RFC8174:
  RFC8620:
  RFC6901:
  RFC4122:

informative:
  RFC8621:
  ULID:
    title: Universally Unique Lexicographically Sortable Identifier
    target: https://github.com/ulid/spec
    date: 2019
  TAILSCALE:
    title: Tailscale — How it works
    target: https://tailscale.com/blog/how-tailscale-works
    date: 2020

--- abstract

This document describes JMAP for Chat, a JMAP capability
({{RFC8620}}) for 1:1 and group text messaging.  It defines the
`urn:kith:chat:1` capability, three data types (Contact, Chat,
Message), and the JMAP methods that operate on them.  It also
defines two server-to-server methods (Peer/deliver, Peer/receipt)
used for mailbox-to-mailbox message delivery.

The protocol is implemented by Kith, a self-hosted, tailnet-native
chat system in which each user runs their own mailbox daemon.  This
document is informational; it describes the Kith implementation.

--- middle

# Introduction

JMAP {{RFC8620}} defines a transport-layer-agnostic, JSON-based
protocol for accessing and mutating application data.  The core
protocol is intentionally generic; application semantics are
expressed through capability URIs declared in the JMAP Session
object.

This document defines the `urn:kith:chat:1` capability, which adds
three first-class data types to a JMAP server:

- **Contact** — a known remote user, identified by a stable opaque
  identity key and associated with a mailbox host address.
- **Chat** — a conversation between two or more participants.
- **Message** — a single message within a Chat.

It also defines two server-to-server methods, `Peer/deliver` and
`Peer/receipt`, used to deliver messages and read receipts between
independent mailbox servers.

The reference implementation is Kith
(https://github.com/MarkAtwood/kith), a single-user, self-hosted
mailbox daemon that binds its HTTPS listener to a Tailscale overlay
network address.  Tailscale's cryptographic identity system provides
the authentication primitive; no additional credential exchange is
required.  Sections of this document that describe authentication
behaviour reflect the Kith implementation.  Other implementations
MAY use different authentication mechanisms.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in
all capitals, as shown here.

Terminology from {{RFC8620}} is used throughout.  In particular:
"server", "client", "account", "method call", "invocation",
"Session object", "state string", and "ResultReference" carry the
meanings defined there.

The term "mailbox" refers to a running server instance serving
exactly one user.  One physical host runs at most one mailbox.

The term "owner" refers to the user whose data a mailbox stores and
serves.

The term "peer" refers to another mailbox server contacting this
mailbox to deliver a message or receipt.

# The urn:kith:chat:1 Capability {#capability}

The `urn:kith:chat:1` capability is advertised in the JMAP Session
object at both the top-level `capabilities` key and within each
account's `accountCapabilities` map.

## Session-Level Capability Object

The value of `capabilities["urn:kith:chat:1"]` is a JSON object with
the following fields:

`maxBodyBytes` (UnsignedInt):
: The maximum number of UTF-8 bytes accepted in a Message `body`
  field.  Servers MUST reject messages exceeding this limit with an
  `invalidArguments` error.  The reference implementation uses
  65536.

`maxAttachmentBytes` (UnsignedInt):
: The maximum size in bytes of a single attachment blob.  The
  reference implementation uses 104857600 (100 MiB).

`supportedBodyTypes` (String[]):
: The set of MIME types accepted in a Message `bodyType` field.
  The reference implementation supports `["text/plain",
  "text/markdown"]`.

## Account-Level Capability Object

The value of `accountCapabilities["urn:kith:chat:1"]` is a JSON
object with the following field:

`role` (String):
: Either `"owner"` or `"peer"`, reflecting the caller's verified
  identity relative to this mailbox.  An owner has access to all
  methods.  A peer may call only `Peer/deliver` and `Peer/receipt`.

## Session Object Extensions

Implementations MAY include the following additional fields in the
Session object to allow remote peers to identify the mailbox owner
without an authenticated method call:

`ownerUserId` (String):
: The stable, opaque identity key of the mailbox owner.

`ownerLogin` (String):
: The login name (typically email-shaped) of the mailbox owner.

# Data Types

## Contact

A Contact represents a remote user known to this mailbox.  Each
Contact has a stable identity key and a mailbox host address at which
their server can be reached.

A Contact object has the following fields:

`id` (String, immutable, server-set):
: A stable, opaque identifier for this contact.  Clients MUST treat
  this as an opaque string and MUST NOT assume any internal
  structure.  In the reference implementation this equals the
  contact's Tailscale user identity string.

`tailscaleUserId` (String, immutable, server-set):
: The Tailscale user identity of this contact.  Treated as an opaque
  key; format varies by Tailscale deployment (numeric on
  Tailscale Inc., OIDC-derived on Headscale).

`login` (String, server-set):
: The login name associated with this contact, typically
  email-shaped.  MUST NOT be empty.

`displayName` (String, optional):
: A human-readable display name.  MAY be absent or empty, especially
  on Headscale deployments without OIDC.  Clients SHOULD fall back
  to `login` when this field is absent or empty.

`mailboxHost` (String):
: The DNS hostname (MagicDNS name or FQDN) of this contact's
  kithd server.  Used to construct the delivery URL for outbound
  messages.

`firstSeenAt` (UTCDate, server-set):
: The time at which this contact was first recorded, in RFC 3339
  format with UTC offset.

`lastSeenAt` (UTCDate, server-set):
: The time of the most recent contact with this user's mailbox.

`blocked` (Boolean):
: When `true`, this mailbox will not accept inbound messages from
  this contact's mailbox, and the owner cannot initiate new messages
  to this contact.  Default: `false`.

## Chat

A Chat represents a conversation between a fixed set of participants.

### Chat ID Computation {#chat-id}

Chat IDs are deterministic and computed independently by each
participant without coordination.  Given the set of Tailscale user
identity strings for all participants:

1. Sort the identity strings lexicographically.
2. Concatenate them, separated by a single null byte (0x00).
3. Compute the SHA-256 hash of the resulting byte string.
4. Encode the hash as a lowercase hexadecimal string.

Both sides MUST compute and compare this value.  A `Peer/deliver`
request whose `chatId` does not match the locally computed value for
the claimed participants MUST be rejected.

### Chat Object Fields

`id` (String, immutable, server-set):
: The deterministic chat ID computed per {{chat-id}}.

`kind` (String, immutable):
: The chat type.  Currently `"direct"` (two participants only).
  Future versions of this capability may add `"group"`.

`participants` (String[], immutable):
: The ordered list of Contact IDs participating in this chat,
  excluding the owner.  In a direct chat this is exactly one
  element.

`createdAt` (UTCDate, immutable, server-set):
: The time this chat was first created on this mailbox.

`lastMessageAt` (UTCDate, optional, server-set):
: The received time of the most recent message in this chat.
  Absent if no messages have been received.

`unreadCount` (UnsignedInt, server-set):
: The number of messages received since the owner last read the
  chat.

## Message

A Message is a single transmission within a Chat.

### Message IDs

Message IDs are ULIDs {{ULID}}: 128-bit, lexicographically
sortable, and generated without coordination.  ULIDs embed a
millisecond-precision timestamp in their high bits, providing
natural time-ordering by ID within a chat.

### Message Object Fields

`id` (String, immutable, server-set):
: A ULID assigned by the receiving mailbox at the time of receipt.

`chatId` (String, immutable):
: The ID of the Chat this message belongs to.

`senderId` (String, immutable, server-set):
: The identity of the sender.  The value `"self"` indicates a
  message composed by the owner of this mailbox.  Any other value
  is the Contact `id` of the remote sender, as verified by the
  authentication layer.

`body` (String):
: The message text.  MUST be valid UTF-8.  Length MUST NOT exceed
  `maxBodyBytes` from the session capability.

`bodyType` (String):
: The MIME type of `body`.  MUST be one of the values in
  `supportedBodyTypes` from the session capability.

`attachments` (Attachment[]):
: Zero or more file attachments.  See {{attachment}}.

`replyTo` (String, optional):
: If present, the `id` of a prior Message in the same Chat that
  this message replies to.  Servers MUST validate that the
  referenced message exists in the same chat before storing.

`sentAt` (UTCDate):
: The time the sender claims to have composed the message.
  This value is peer-supplied and MUST be treated as untrusted.
  Implementations SHOULD use `receivedAt` for display ordering.

`receivedAt` (UTCDate, immutable, server-set):
: The time this mailbox received the message, according to the
  local clock.  This value is authoritative for ordering.

`deliveryState` (String, server-set):
: One of `"pending"`, `"delivered"`, `"failed"`, or `"received"`.
  `"pending"`: queued in the outbox, not yet delivered to the
  recipient's mailbox.  `"delivered"`: the recipient's mailbox
  accepted the message.  `"failed"`: delivery failed after all
  retries.  `"received"`: an inbound message (from a peer).

`deliveredAt` (UTCDate, optional, server-set):
: The time the outbound delivery was acknowledged by the recipient's
  mailbox.  Present only when `deliveryState` is `"delivered"`.

`readAt` (UTCDate, optional, server-set):
: The time the owner acknowledged reading this message.

## Attachment {#attachment}

An Attachment references a blob stored on the server.

`blobId` (String):
: An opaque server-assigned identifier for the uploaded blob.
  Used to construct download URLs per the Session `downloadUrl`
  template.

`filename` (String):
: The original filename.  MUST NOT contain path separators (`/`,
  `\`) or null bytes.  Servers MUST reject filenames that do not
  satisfy these constraints.

`contentType` (String):
: A valid MIME type string.  Servers MUST reject values that do not
  parse as a valid MIME type.

`size` (UnsignedInt):
: The size of the blob in bytes.  Servers MUST verify this matches
  the actual byte count of the stored blob.

`sha256` (String):
: The SHA-256 hash of the blob contents, hex-encoded lowercase.
  Servers SHOULD verify this matches the uploaded content.

# Methods

## Contact Methods

### Contact/get

Standard JMAP `/get` method ({{RFC8620}} Section 5.1).

Request arguments (in addition to standard):
: None beyond `accountId` and `ids`.

Response arguments (in addition to standard):
: `list` (Contact[]) — The requested Contact objects.

### Contact/set

Standard JMAP `/set` method ({{RFC8620}} Section 5.3).

`create` is not supported by clients; contacts are created
automatically by the server when a peer delivers a message.
Attempting to create a Contact via `Contact/set` MUST return a
`forbidden` SetError.

`update` supports the following mutable fields: `blocked`.
Attempting to update immutable fields MUST return an `invalidProperties`
SetError.

`destroy` is not supported.  Attempting to destroy a Contact MUST
return a `forbidden` SetError.

### Contact/changes

Standard JMAP `/changes` method ({{RFC8620}} Section 5.2).

### Contact/query

Standard JMAP `/query` method ({{RFC8620}} Section 5.5).

Filterable properties: `blocked` (Boolean).
Sortable properties: `lastSeenAt`, `login`.

## Chat Methods

### Chat/get

Standard JMAP `/get` method.

### Chat/set

Standard JMAP `/set` method.

`create` accepts:
: `contactId` (String, required) — The Contact `id` of the other
  participant.  The server computes the Chat ID per {{chat-id}} from
  the owner's identity and the contact's `tailscaleUserId`.  If a
  Chat with this ID already exists, the existing Chat is returned in
  `updated` rather than `created`.

`update` and `destroy` are not supported.

### Chat/changes

Standard JMAP `/changes` method.

### Chat/query

Standard JMAP `/query` method.

Default sort: `lastMessageAt` descending (most recently active
first).  Chats with no messages sort last.

## Message Methods

### Message/get

Standard JMAP `/get` method.

Additional filter argument:
: `chatId` (String, optional) — If present, return only messages
  belonging to the specified Chat.

### Message/set

Standard JMAP `/set` method.

`create` accepts:
: `chatId` (String, required), `body` (String, required), `bodyType`
  (String, required), `sentAt` (UTCDate, required), `attachments`
  (Attachment[], optional), `replyTo` (String, optional).

  The server assigns `id`, `senderId`, `receivedAt`,
  `deliveryState`, and related fields.  After creating the Message
  record, the server MUST enqueue the message for delivery to the
  contact's mailbox.

`update` is limited to: `readAt`.

`destroy` is not supported.

### Message/changes

Standard JMAP `/changes` method.

### Message/query

Standard JMAP `/query` method.

Required filter:
: `chatId` (String) — All Message/query requests MUST include a
  `chatId` filter.

Default sort: `receivedAt` ascending (oldest first).

### Message/queryChanges

Standard JMAP `/queryChanges` method ({{RFC8620}} Section 5.6).

# Server-to-Server Methods {#peer-methods}

The following methods are for use between mailbox servers only.
They are not available to owner clients.  A server MUST verify
the caller's identity before processing these methods and MUST
return a `forbiddenMethod` error if the caller is not a known peer.

## Peer/deliver

Delivers an inbound message from a remote mailbox to this one.

Method name: `Peer/deliver`

Request arguments:

`accountId` (String):
: The account ID on the receiving server.

`chatId` (String):
: The deterministic Chat ID for this conversation, as computed per
  {{chat-id}}.  The server MUST recompute the expected Chat ID from
  the verified sender identity and the owner's identity, and MUST
  reject the request if they do not match.

`senderTailscaleUserId` (String):
: The Tailscale user identity of the sender.  MUST equal the
  verified identity of the connecting peer (as returned by the
  authentication layer).  The server MUST reject the request if
  these values do not match.

`message` (Object):
: The message to deliver.  Contains:
  - `id` (String) — A sender-assigned ULID for idempotency.
  - `body` (String) — Message text; validated per `maxBodyBytes`.
  - `bodyType` (String) — MIME type; validated per `supportedBodyTypes`.
  - `sentAt` (UTCDate) — Sender's claimed composition time; stored
    as-is without validation.
  - `attachments` (Object[]) — Attachment metadata (same fields as
    Attachment in {{attachment}}), plus `fetchUrl` (String): the URL
    from which this server should fetch the blob content.
  - `replyTo` (String, optional) — Reply-to message ID.

### Delivery Validation

The server MUST perform the following checks before storing the
message, in order:

1. Verify the caller's identity via the authentication layer.
2. Confirm `senderTailscaleUserId` matches the verified identity.
3. Recompute the expected Chat ID and compare to `chatId`.
4. Check that the sender is not blocked.
5. Validate `body` length against `maxBodyBytes`.
6. Validate `bodyType` against `supportedBodyTypes`.
7. Validate each attachment's `filename`, `contentType`, and `size`.
8. For each attachment, fetch the blob from `fetchUrl`, verify its
   size against the claimed `size`, and verify its SHA-256 against
   the claimed `sha256`.

A failure at any step MUST result in the request being rejected and
no data being stored.

Response arguments:

`accountId` (String):
: Echoed from the request.

`messageId` (String):
: The locally assigned ULID for the stored message.

`receivedAt` (UTCDate):
: The time the receiving server stored the message.

## Peer/receipt

Notifies the sender's mailbox that a message was received and
stored by the recipient.

Method name: `Peer/receipt`

Request arguments:

`accountId` (String):
: The account ID on the receiving server.

`messageId` (String):
: The sender-assigned ULID of the delivered message (the `id` field
  from the `Peer/deliver` request).

`receivedAt` (UTCDate):
: The time the recipient's server stored the message.

Response arguments:

`accountId` (String):
: Echoed from the request.

# Push Notifications

Servers implementing `urn:kith:chat:1` MUST support the EventSource
push mechanism defined in {{RFC8620}} Section 7.3.

The `eventSourceUrl` in the Session object follows the template
defined in {{RFC8620}}, with `{types}`, `{closeafter}`, and `{ping}`
placeholders.

When the state of any data type advances, the server emits an event:

~~~
event: state
data: {"changed":{"<accountId>":{"Message":"<newState>","Chat":"<newState>"}}}
~~~

Clients receiving this event SHOULD call the corresponding
`/changes` method to retrieve the delta.  If `/changes` returns
`cannotCalculateChanges`, clients MUST fall back to a full `/get`.

# Blob Storage

Attachment blobs are stored and retrieved via the standard JMAP
upload and download endpoints defined in {{RFC8620}} Section 6.

## Upload

`POST <uploadUrl>` with the file content as the request body.
Content-Type MUST be set to the attachment's MIME type.

Response (HTTP 200):

~~~json
{
  "blobId": "<server-assigned-id>",
  "type":   "<content-type>",
  "size":   <bytes>,
  "sha256": "<hex-encoded-hash>"
}
~~~

## Download

`GET <downloadUrl>` with `{accountId}`, `{blobId}`, `{name}`, and
`{type}` placeholders substituted.  Each value MUST be
percent-encoded before substitution.

# Outbox and Retry

Outbound messages are stored in a persistent outbox before delivery.
The server MUST attempt delivery to the recipient's mailbox via
`Peer/deliver`.  On failure, the server MUST retry using exponential
backoff.  The `deliveryState` field reflects current outbox status.

Message IDs (ULIDs) provide natural idempotency: a receiving server
that sees a duplicate ULID for the same Chat MAY silently accept and
discard the duplicate without returning an error.

# Authentication

Authentication is outside the scope of this document.  The Kith
reference implementation uses Tailscale {{TAILSCALE}} as its
authentication layer: the server binds exclusively to the Tailscale
overlay network interface, and the verified identity of any incoming
TCP connection is obtained by querying the local Tailscale daemon.

Other implementations MAY use any HTTP authentication mechanism
compatible with {{RFC8620}}.

The following access control rules apply regardless of the
authentication mechanism used:

- A caller identified as the **owner** may call any method defined
  in {{capability}} through {{peer-methods}}.
- A caller identified as a **peer** may call only `Peer/deliver`
  and `Peer/receipt`.
- Any other caller MUST receive HTTP 401.

# IANA Considerations

## JMAP Capability Registration

IANA is requested to register the following entry in the "JMAP
Capabilities" registry:

Capability Name:
: `urn:kith:chat:1`

Intended Use:
: common

Change Controller:
: Mark Atwood (mark@reviewcommit.com)

Reference:
: This document.

Security and Privacy Considerations:
: See {{security}} of this document.

# Security Considerations {#security}

## Identity Verification

The `senderTailscaleUserId` field in `Peer/deliver` is
attacker-controlled.  Servers MUST compare it against the verified
identity obtained from the authentication layer before any database
write.  Verification MUST precede storage.

## Input Validation

All fields arriving in `Peer/deliver` are attacker-controlled and
MUST be validated before use:

- `body`: validate UTF-8, enforce `maxBodyBytes`.
- `bodyType`: validate against `supportedBodyTypes`; reject
  unrecognised values.
- `filename`: reject values containing path separators or null bytes.
- `contentType`: reject values that do not parse as valid MIME.
- `size`: verify against actual blob byte count after fetch.
- `sha256`: verify against actual blob content after fetch.
- `sentAt`: store as-is; do not use for ordering.
- `chatId`: recompute locally and reject if mismatch.

## Attachment Fetch SSRF

When fetching attachment blobs from `fetchUrl` during `Peer/deliver`
processing, servers MUST restrict outbound connections to the
overlay network (e.g., the Tailscale interface).  Unrestricted fetch
URLs are a server-side request forgery vector.

## Denial of Service

Servers MUST enforce `maxBodyBytes` and `maxAttachmentBytes` at
parse time, before any storage operation, to limit resource
consumption from oversized payloads.

## Message Ordering

`sentAt` is peer-supplied and MUST NOT be used for security-relevant
ordering decisions.  `receivedAt` is set by the receiving server and
is the authoritative timestamp for display and ordering.

## Chat ID Integrity

The deterministic Chat ID computation ({{chat-id}}) ensures that
both participants independently derive the same identifier.  A peer
that supplies a `chatId` that does not match the locally computed
value is either misconfigured or attempting to inject a message into
the wrong conversation.  Servers MUST reject such requests.

--- back

# Acknowledgements

The author thanks the JMAP working group for RFC 8620, which
provided the protocol foundation that made this capability
straightforward to define.
