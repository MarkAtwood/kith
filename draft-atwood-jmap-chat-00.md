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

informative:
  RFC8621:
  ULID:
    title: Universally Unique Lexicographically Sortable Identifier
    target: https://github.com/ulid/spec
    date: 2019
  KITH:
    title: Kith — tailnet-native chat
    target: https://github.com/MarkAtwood/kith
    date: 2026
  TAILSCALE:
    title: Tailscale — How it works
    target: https://tailscale.com/blog/how-tailscale-works
    date: 2020

--- abstract

This document defines JMAP for Chat, a JMAP capability ({{RFC8620}})
for direct and group text messaging between users who each operate
their own mailbox server.  It defines the `urn:jmap:chat:1`
capability; three data types (Contact, Chat, Message); JMAP methods
for each type; and four server-to-server methods (Peer/deliver,
Peer/receipt, Peer/typing, Peer/retract) for direct
mailbox-to-mailbox communication.

The protocol covers the feature set common to contemporary messaging
systems: group chat with membership roles, message reactions, editing,
deletion, threading, @mentions, typing indicators, read receipts per
participant, presence, pinned messages, and per-chat notification
settings.

--- middle

# Introduction

JMAP {{RFC8620}} defines a JSON-based protocol for accessing and
mutating application data.  The core protocol is intentionally
generic; application semantics are expressed through capability URIs
declared in the JMAP Session object.  {{RFC8621}} defines JMAP for
Mail.  This document defines an analogous capability for real-time
chat.

The design assumes a **mailbox-per-user** topology: each participant
runs their own JMAP server (a "mailbox") that stores only their own
messages.  There is no central server, no central message store, and
no central operator.  Mailboxes exchange messages directly with each
other over a secure transport.

Authentication is handled entirely at the transport layer.  The
protocol requires only that the authentication layer provide a stable,
opaque user identity string for each connection.  How that identity
is established — overlay network membership, mutual TLS, bearer
tokens, or any other mechanism — is outside the scope of this
document and left to the deployment.

The reference implementation of this capability is Kith {{KITH}}.
Implementation-specific details are noted in {{impl-notes}}.

# Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in
all capitals, as shown here.

Terminology from {{RFC8620}} is used throughout.

The following terms are specific to this document:

Mailbox:
: A JMAP server instance serving exactly one user.

Owner:
: The user whose data a mailbox stores and serves.

Peer:
: Another mailbox server communicating with this mailbox.

userId:
: An opaque, stable string provided by the authentication layer that
  uniquely identifies a user within the deployment.  The protocol
  treats this as an uninterpreted byte string; no structure is
  assumed.

# The urn:jmap:chat:1 Capability {#capability}

The `urn:jmap:chat:1` capability is advertised in the JMAP Session
object at both the top-level `capabilities` key and within each
account's `accountCapabilities` map.

## Session-Level Capability Object

The value of `capabilities["urn:jmap:chat:1"]` is a JSON object with
the following fields:

`maxBodyBytes` (UnsignedInt):
: Maximum UTF-8 byte length of a Message `body`.  Servers MUST
  reject messages exceeding this limit with `invalidArguments`.

`maxAttachmentBytes` (UnsignedInt):
: Maximum size in bytes of a single attachment blob.

`maxAttachmentsPerMessage` (UnsignedInt):
: Maximum number of attachments per message.

`maxGroupMembers` (UnsignedInt):
: Maximum number of members in a group chat.

`supportedBodyTypes` (String[]):
: MIME types accepted in `bodyType`.  MUST include `"text/plain"`.

`supportsThreads` (Boolean):
: Whether this server supports the optional thread model defined in
  {{threads}}.  Clients MUST NOT send `threadRootId` to servers
  where this is `false`.

## Account-Level Capability Object

The value of `accountCapabilities["urn:jmap:chat:1"]` is a JSON
object with the following field:

`role` (String):
: Either `"owner"` or `"peer"`.

## Session Object Extensions

Servers MAY include in the Session object:

`ownerUserId` (String):
: The stable user identity of the mailbox owner.

`ownerLogin` (String):
: A human-readable login name for the mailbox owner.

# Data Types

## Contact

A Contact represents a remote user known to this mailbox.

`id` (String, immutable, server-set):
: Stable, opaque identifier.  Servers SHOULD derive this from the
  contact's verified userId.

`userId` (String, immutable, server-set):
: The contact's userId as provided by the authentication layer.

`login` (String, server-set):
: Human-readable login name.  MUST NOT be empty.

`displayName` (String, optional):
: Human-readable display name.  MAY be absent or empty.  Clients
  SHOULD fall back to `login`, then `userId`.

`serverUrl` (String):
: Base HTTPS URL of this contact's mailbox.  Used for outbound
  delivery.

`firstSeenAt` (UTCDate, server-set):
: Time this contact was first recorded.

`lastSeenAt` (UTCDate, server-set):
: Time of most recent interaction with this contact's mailbox.

`presence` (String, server-set):
: Last known presence state: `"online"`, `"away"`, `"offline"`, or
  `"unknown"`.  This value is informational; servers update it on a
  best-effort basis.

`lastActiveAt` (UTCDate, optional, server-set):
: Time the contact was last observed to be active.

`blocked` (Boolean):
: When `true`, this mailbox will not accept inbound messages from
  this contact.  Default: `false`.

## ChatMember

A ChatMember describes one participant in a group Chat.

`userId` (String):
: The participant's userId.

`role` (String):
: Either `"admin"` or `"member"`.  Admins may add and remove
  members and update chat metadata.

`joinedAt` (UTCDate):
: Time this participant joined the chat.

`invitedBy` (String, optional):
: The userId of the member who added this participant.

## Chat

A Chat is a conversation between two or more participants.

### Chat ID Computation {#chat-id}

Chat IDs are deterministic.  Given the set of userId strings for
all participants (including the owner):

1. Sort the strings lexicographically by UTF-8 byte value.
2. Concatenate them separated by a single null byte (0x00).
3. Compute the SHA-256 hash of the result.
4. Encode as lowercase hexadecimal (64 characters).

Both sides MUST compute and verify this value.  A `Peer/deliver`
whose `chatId` does not match the locally computed value MUST be
rejected.

### Chat Object Fields

`id` (String, immutable, server-set):
: Deterministic chat ID per {{chat-id}}.

`kind` (String, immutable):
: `"direct"` (exactly two participants) or `"group"`.

`name` (String, optional):
: Display name of the chat.  Required for `kind: "group"`.  Not
  used for direct chats (display name is derived from the contact).

`description` (String, optional):
: Short description of the group chat.

`avatarBlobId` (String, optional):
: blobId of the chat avatar image.

`participants` (String[]):
: For a direct chat: the single Contact `id` of the other party.
  For a group chat: all Contact `id` values of non-owner members.

`members` (ChatMember[], optional):
: Full membership list with roles.  Present for group chats.
  Absent for direct chats.

`createdAt` (UTCDate, immutable, server-set):
: Time this chat was first recorded on this mailbox.

`lastMessageAt` (UTCDate, optional, server-set):
: Received time of the most recent message.

`unreadCount` (UnsignedInt, server-set):
: Messages received since the owner last read this chat.

`pinnedMessageIds` (String[]):
: Ordered list of pinned message IDs, most-recently-pinned first.
  Empty by default.

`muted` (Boolean):
: When `true`, push notifications for this chat are suppressed.
  Default: `false`.  Owner-side preference; not shared with peers.

`muteUntil` (UTCDate, optional):
: If present, muting is lifted after this time.  Servers SHOULD
  clear `muted` and `muteUntil` automatically once the time passes.

`messageExpirySeconds` (UnsignedInt, optional):
: If present and non-zero, messages older than this many seconds are
  automatically deleted by the server.  Applies to all participants
  independently; each mailbox enforces its own timer.  Setting this
  on a direct chat SHOULD be communicated to the peer via
  `Peer/deliver` metadata so the peer can apply the same policy.

## Reaction

A Reaction is an emoji response to a Message by one participant.

`emoji` (String):
: One or more Unicode code points representing the reaction.
  Implementations SHOULD limit this to a single grapheme cluster.

`senderId` (String):
: `"self"` for the owner's reaction, or a Contact `id`.

`sentAt` (UTCDate):
: Time the reaction was added.

## Mention

A Mention identifies a user referenced within a message body.

`userId` (String):
: The userId of the mentioned participant.

`offset` (UnsignedInt):
: Byte offset of the mention text within `body`.

`length` (UnsignedInt):
: Byte length of the mention text within `body`.

## MessageRevision

A MessageRevision records one historical version of a Message.

`body` (String):
: The prior body text.

`bodyType` (String):
: The prior MIME type.

`editedAt` (UTCDate):
: The time at which the message was edited away from this version.

## Message

A Message is a single transmission within a Chat.

### Message IDs

Message IDs are ULIDs {{ULID}}.  ULIDs embed a millisecond-precision
timestamp and sort lexicographically by time, enabling ordered
retrieval without a separate sort field.  Receiving servers that see
a duplicate ULID for the same Chat MAY silently discard it.

### Message Object Fields

`id` (String, immutable, server-set):
: ULID assigned by the receiving mailbox.

`chatId` (String, immutable):
: ID of the containing Chat.

`senderId` (String, immutable, server-set):
: `"self"` for owner-composed messages; a Contact `id` for inbound
  messages.

`body` (String):
: Message text.  MUST be valid UTF-8.  Empty string when the
  message has been deleted.

`bodyType` (String):
: MIME type of `body`.  MUST be in `supportedBodyTypes`.

`attachments` (Attachment[]):
: Zero or more file attachments.

`mentions` (Mention[]):
: Structured @mention annotations.  Empty by default.

`reactions` (Reaction[]):
: Emoji reactions to this message.  Empty by default.

`replyTo` (String, optional):
: The `id` of the Message this is a direct reply to.  Servers MUST
  validate this ID exists in the same Chat.

`threadRootId` (String, optional):
: The `id` of the root Message of the thread this message belongs
  to.  Only meaningful when `supportsThreads` is `true`.  If
  `replyTo` is set and `threadRootId` is absent, the thread root is
  `replyTo`.  See {{threads}}.

`replyCount` (UnsignedInt, server-set):
: Number of messages in this chat that have `replyTo` equal to this
  message's `id`.  Present only when `supportsThreads` is `true`.

`sentAt` (UTCDate):
: Sender's claimed composition time.  Peer-supplied; MUST be treated
  as untrusted.  Use `receivedAt` for ordering.

`receivedAt` (UTCDate, immutable, server-set):
: Time this mailbox stored the message.  Authoritative for ordering.

`deliveryState` (String, server-set):
: For direct chats: `"pending"`, `"delivered"`, `"failed"`, or
  `"received"`.  For group chats, this reflects the aggregate
  state; see `deliveryReceipts`.

`deliveryReceipts` (Object, optional, server-set):
: For group chats, a map of `{userId → {deliveredAt, readAt}}` for
  each non-owner participant.  Present only for messages where
  `senderId` is `"self"`.

`deliveredAt` (UTCDate, optional, server-set):
: Time the outbound delivery was first acknowledged.

`readAt` (UTCDate, optional, server-set):
: Time the owner acknowledged reading this message.

`editedAt` (UTCDate, optional, server-set):
: Time of the most recent edit.  Absent if the message has not been
  edited.

`editHistory` (MessageRevision[], optional, server-set):
: Ordered list of prior versions, oldest first.  Populated on edit.
  Servers MAY limit the number of retained revisions.

`deletedAt` (UTCDate, optional, server-set):
: Time the message was deleted.  When set, `body` is cleared to an
  empty string and `attachments` is cleared.  The message record is
  retained as a tombstone.

`deletedForAll` (Boolean, optional, server-set):
: When `true`, the delete was propagated to all participants via
  `Peer/retract`.  When `false` or absent, the delete is local only.

## Attachment {#attachment}

`blobId` (String):
: Opaque server-assigned blob identifier.

`filename` (String):
: Original filename.  MUST NOT contain `/`, `\`, or null bytes.

`contentType` (String):
: Valid MIME type string.

`size` (UnsignedInt):
: Blob size in bytes.  Servers MUST verify against actual content.

`sha256` (String):
: Lowercase hex SHA-256 of blob content.  Servers SHOULD verify.

# Methods

## Contact Methods

Contacts are created automatically when a peer delivers a message.
Clients cannot create or destroy contacts directly.

### Contact/get

Standard JMAP `/get` ({{RFC8620}} Section 5.1).

### Contact/set

Standard JMAP `/set` ({{RFC8620}} Section 5.3).

`create` and `destroy` are not supported; both MUST return
`forbidden`.

`update` supports: `blocked`, `displayName`.

### Contact/changes

Standard JMAP `/changes` ({{RFC8620}} Section 5.2).

### Contact/query

Standard JMAP `/query` ({{RFC8620}} Section 5.5).

Filter properties: `blocked` (Boolean), `presence` (String).
Sort properties: `lastSeenAt`, `login`, `lastActiveAt`.

## Chat Methods

### Chat/get

Standard JMAP `/get`.

### Chat/set

Standard JMAP `/set`.

#### Creating a Direct Chat

`create` with `kind: "direct"` accepts:

`contactId` (String, required):
: Contact `id` of the other participant.  The server computes the
  Chat ID per {{chat-id}}.  If a Chat with this ID already exists,
  the server MUST return the existing Chat in `updated`.

#### Creating a Group Chat

`create` with `kind: "group"` accepts:

`name` (String, required):
: Display name of the group.

`memberUserIds` (String[], required):
: userIds of initial non-owner members.  The server resolves these
  to Contact records, creating them if necessary.  MUST NOT exceed
  `maxGroupMembers - 1` (excluding the owner).

`description` (String, optional):
: Initial group description.

`avatarBlobId` (String, optional):
: blobId of the initial group avatar.

`messageExpirySeconds` (UnsignedInt, optional):
: Initial message expiry timer.

#### Updating a Chat

`update` supports the following fields:

- For all chat kinds: `muted`, `muteUntil`, `pinnedMessageIds`,
  `messageExpirySeconds`.
- For group chats only (requires `"admin"` role): `name`,
  `description`, `avatarBlobId`.

#### Managing Group Members

Member changes are expressed through two special update keys:

`addMembers` (Object[]):
: Each entry contains `userId` (String) and optional `role` (String,
  default `"member"`).

`removeMembers` (String[]):
: List of userIds to remove from the group.

`updateMemberRole` (Object[]):
: Each entry contains `userId` (String) and `role` (String).
  Requires admin role.

### Chat/changes

Standard JMAP `/changes`.

### Chat/query

Standard JMAP `/query`.

Filter properties: `kind` (String), `muted` (Boolean).
Default sort: `lastMessageAt` descending; chats with no messages
sort last.

## Message Methods

### Message/get

Standard JMAP `/get`.

### Message/set

Standard JMAP `/set`.

#### Creating a Message

`create` accepts: `chatId` (String, required), `body` (String,
required), `bodyType` (String, required), `sentAt` (UTCDate,
required), `attachments` (Attachment[], optional), `mentions`
(Mention[], optional), `replyTo` (String, optional),
`threadRootId` (String, optional).

The server assigns `id`, `senderId`, `receivedAt`,
`deliveryState`, and delivery timestamp fields, then enqueues
the message for outbound delivery.

#### Editing a Message

`update` on a message where `senderId` is `"self"` and
`deletedAt` is absent.  Permitted fields: `body`, `bodyType`,
`mentions`.

When an edit is applied, the server MUST:

1. Append a MessageRevision to `editHistory` capturing the prior
   `body`, `bodyType`, and current time as `editedAt`.
2. Replace `body` and `bodyType` with the new values.
3. Set `editedAt` to the current server time.
4. Propagate the edit to peers via `Peer/deliver` update
   semantics (see {{peer-deliver}}).

#### Adding and Removing Reactions

Reaction changes are expressed through two special update keys:

`addReaction` (Object):
: Contains `emoji` (String).  The server appends a Reaction with
  `senderId: "self"` and current time.  Servers SHOULD enforce a
  limit on distinct emoji per message per sender.

`removeReaction` (Object):
: Contains `emoji` (String).  Removes the owner's reaction with
  that emoji, if present.

#### Pinning and Unpinning

Pinning is expressed via Chat/set `update` on `pinnedMessageIds`,
not via Message/set.

#### Deleting a Message

`update` with `deletedAt: <current-time>` initiates deletion.

- If `deletedForAll: true` is also set, the server MUST send
  `Peer/retract` to all participants and set `deletedForAll: true`
  on the stored record.
- If `deletedForAll` is absent or `false`, the deletion is local
  only: `body` and `attachments` are cleared on this mailbox, and
  no peer notification is sent.

Clients MAY delete only messages where `senderId` is `"self"` or
where local-only deletion is intended.  Servers MUST reject
`deletedForAll: true` for messages where `senderId` is not
`"self"`.

#### Marking as Read

`update` with `readAt: <timestamp>` marks the message as read by
the owner.

### Message/changes

Standard JMAP `/changes`.

### Message/query

Standard JMAP `/query`.

All requests MUST include a `chatId` filter.

Additional filter properties:

`text` (String, optional):
: Full-text search over `body`.  Servers that do not support
  full-text search MUST return an `unsupportedFilter` error.

`threadRootId` (String, optional):
: Return only messages in the specified thread.  Only meaningful
  when `supportsThreads` is `true`.

`hasAttachment` (Boolean, optional):
: Filter to messages with or without attachments.

`hasMention` (Boolean, optional):
: Filter to messages that mention the owner's userId.

Default sort: `receivedAt` ascending.

### Message/queryChanges

Standard JMAP `/queryChanges` ({{RFC8620}} Section 5.6).

# Optional: Thread Model {#threads}

Servers that advertise `supportsThreads: true` support structured
conversation threads within a Chat.

A thread is a set of Messages sharing a common `threadRootId`.
The root message has `threadRootId` absent; all replies carry the
root's `id` as `threadRootId`.

`Message/query` with a `threadRootId` filter returns all messages
in a thread.  `replyCount` on each message gives the number of
direct replies.

Servers that do not support threads MUST advertise
`supportsThreads: false` and MUST return an `unsupportedFilter`
error if a client sends a `threadRootId` filter.

# Server-to-Server Methods {#peer-methods}

The following methods are used between mailbox servers only.  Callers
without the `"peer"` role MUST receive `forbiddenMethod`.

## Peer/deliver {#peer-deliver}

Delivers a message, edit, or reaction from a remote mailbox.

Method name: `Peer/deliver`

Request arguments:

`accountId` (String):
: Account ID on the receiving server.

`chatId` (String):
: Deterministic Chat ID per {{chat-id}}.  The receiver MUST
  recompute and verify this value.

`senderUserId` (String):
: The sender's userId.  MUST match the identity provided by the
  authentication layer.

`participantUserIds` (String[]):
: The full list of userIds for all chat participants, including
  the sender.  Required for group chats; used by the receiver to
  verify `chatId`.

`message` (Object):
: The message to deliver.  Contains all fields of a Message plus:

  - `id` (String) — Sender-assigned ULID (idempotency key).
  - `fetchUrl` (String, per attachment) — URL from which the
    receiver fetches each attachment blob.

`edit` (Object, optional):
: If present, this delivery carries an edit to an existing message.
  Contains `messageId` (String), `body` (String), `bodyType`
  (String), `editedAt` (UTCDate).  The `message` field MUST be
  absent when `edit` is present.

`reactionUpdate` (Object, optional):
: If present, adds or removes a reaction on an existing message.
  Contains `messageId` (String), `emoji` (String), `action`
  (`"add"` or `"remove"`), `sentAt` (UTCDate).  The `message`
  field MUST be absent when `reactionUpdate` is present.

`messageExpirySeconds` (UnsignedInt, optional):
: The sender's current `messageExpirySeconds` for this chat, if
  set.  The receiver MAY apply this policy locally.

### Delivery Validation

Before storing anything, the server MUST in order:

1. Verify the caller's identity via the authentication layer.
2. Confirm `senderUserId` matches the verified identity.
3. Recompute the Chat ID from `participantUserIds` and compare
   to `chatId`.
4. Confirm the sender is not blocked.
5. Validate `body` length against `maxBodyBytes`.
6. Validate `bodyType` against `supportedBodyTypes`.
7. Validate each attachment's `filename`, `contentType`, `size`.
8. Fetch each attachment from `fetchUrl`; verify byte count and
   SHA-256.

Failure at any step MUST result in rejection with no data stored.

Response arguments:

`accountId` (String), `messageId` (String, the receiver's ULID),
`receivedAt` (UTCDate).

## Peer/receipt

Notifies the sending mailbox of successful storage.

Method name: `Peer/receipt`

Request: `accountId`, `messageId` (sender-assigned ULID),
`receivedAt` (UTCDate), `readerUserId` (String, the userId of the
acknowledging user — allows group receipt aggregation).

Response: `accountId`.

## Peer/typing

Notifies a remote mailbox that the owner is typing (or has stopped).

Method name: `Peer/typing`

Request arguments:

`accountId` (String), `chatId` (String), `senderUserId` (String,
MUST match the authenticated identity), `typing` (Boolean).

Response: `accountId`.

The receiving server MUST NOT store this event.  It MUST forward
a `typing` push event (see {{push}}) to the owner's connected
clients.

## Peer/retract

Requests that a remote mailbox delete a specific message.

Method name: `Peer/retract`

Request arguments:

`accountId` (String), `chatId` (String), `senderUserId` (String,
MUST match authenticated identity), `messageId` (String, the
sender-assigned ULID of the message to retract).

The receiving server MUST only honour this request if the
`senderUserId` matches the sender recorded on the stored message.
On success, the server MUST tombstone the message (`deletedAt`,
`body` cleared) and set `deletedForAll: true`.

Response: `accountId`, `retractedAt` (UTCDate).

# Push Notifications {#push}

Servers MUST support the EventSource mechanism defined in
{{RFC8620}} Section 7.3.

## State-Change Events

When data-type state advances, the server emits:

~~~
event: state
data: {"changed":{"<accountId>":{"Message":"<s>","Chat":"<s>","Contact":"<s>"}}}
~~~

Clients SHOULD call the corresponding `/changes` method.  On
`cannotCalculateChanges`, fall back to `/get`.

## Typing Events

When a `Peer/typing` is received, the server emits to the owner's
connected clients:

~~~
event: typing
data: {"chatId":"<id>","senderId":"<contactId>","typing":<bool>}
~~~

This event MUST NOT be stored and carries no state token.

## Presence Events

When a contact's presence changes, the server emits:

~~~
event: presence
data: {"contactId":"<id>","presence":"<state>","lastActiveAt":"<ts>"}
~~~

# Blob Storage

Upload and download use the standard JMAP blob endpoints from
{{RFC8620}} Section 6, via the `uploadUrl` and `downloadUrl`
templates in the Session object.

## Upload

`POST <uploadUrl>` with the blob as request body.

Response (HTTP 200):

~~~json
{
  "blobId":  "<id>",
  "type":    "<mime-type>",
  "size":    <bytes>,
  "sha256":  "<hex>"
}
~~~

## Download

`GET <downloadUrl>` with placeholders percent-encoded.

# Outbox and Delivery

Outbound messages MUST be queued in a persistent outbox before the
first delivery attempt.  Servers MUST retry with exponential backoff.

For group chats, the sender's mailbox delivers independently to each
participant's mailbox and tracks per-recipient state in
`deliveryReceipts`.  The aggregate `deliveryState` is `"delivered"`
only when all participants have acknowledged.

ULID message IDs provide natural idempotency.  Duplicate ULIDs for
the same Chat MAY be silently discarded by the receiver.

# Authentication

Authentication is outside the scope of this document.  The protocol
requires only that the deployment provide a stable, opaque `userId`
per connection.

Access control:

- **Owner** (identity matches mailbox owner's userId): all methods.
- **Peer** (identity matches a known contact's userId):
  `Peer/deliver`, `Peer/receipt`, `Peer/typing`, `Peer/retract` only.
- **Other**: HTTP 401.

# IANA Considerations

## JMAP Capability Registration

IANA is requested to register the following entry in the "JMAP
Capabilities" registry:

Capability Name:
: `urn:jmap:chat:1`

Intended Use:
: common

Change Controller:
: Mark Atwood (mark@reviewcommit.com)

Reference:
: This document.

Security and Privacy Considerations:
: See {{security}} of this document.

# Security Considerations {#security}

## Identity Verification Ordering

`senderUserId` in `Peer/deliver`, `Peer/typing`, and `Peer/retract`
is caller-supplied and MUST be treated as untrusted.  The server MUST
compare it against the verified identity from the authentication layer
before any storage or action.  Verification MUST precede all effects.

## Input Validation

All peer-supplied fields are attacker-controlled:

- `body`: validate UTF-8; enforce `maxBodyBytes`.
- `bodyType`: validate against `supportedBodyTypes`.
- `filename`: reject values containing `/`, `\`, or null bytes.
- `contentType`: reject syntactically invalid MIME values.
- `size`: verify against actual blob byte count after fetch.
- `sha256`: verify against actual blob content after fetch.
- `sentAt`: store as-is; never use for ordering.
- `chatId`: recompute locally from `participantUserIds`; reject
  mismatches.
- `emoji` in reactions: validate as a reasonable grapheme cluster;
  enforce a per-message-per-sender reaction limit.
- `mentions`: validate that `offset + length` does not exceed the
  byte length of `body`.

## Blob Fetch and SSRF

When fetching blobs from peer-supplied `fetchUrl` values, servers
MUST restrict outbound connections to the known peer address space.
Arbitrary URL fetch is an SSRF vector.

## Denial of Service

Enforce `maxBodyBytes` and `maxAttachmentBytes` at parse time, before
any fetch or storage.  Enforce `maxAttachmentsPerMessage` and
`maxGroupMembers` at creation time.

## Timestamp Trust

`sentAt` is peer-supplied.  `receivedAt` is server-set.  Use only
`receivedAt` for ordering, deduplication, and expiry calculations.

## Chat ID Integrity

The deterministic Chat ID ({{chat-id}}) prevents message injection
into wrong conversations.  Verify before storage.

## Retract Authorization

`Peer/retract` MUST verify that `senderUserId` matches the `senderId`
recorded on the stored message.  Peers MUST NOT be permitted to
retract messages they did not send.

## Typing Indicator Amplification

`Peer/typing` MUST NOT be stored or forwarded beyond the owner's
connected clients.  Implementations MUST rate-limit inbound
`Peer/typing` calls per peer to prevent event-amplification attacks.

## Message Expiry

Message expiry timers are enforced independently per mailbox.  A
peer setting `messageExpirySeconds` in a `Peer/deliver` payload is
providing a request, not a command.  The receiving mailbox MAY
ignore or override this value.

--- back

# Implementation Notes: Kith {#impl-notes}

This appendix is informative.

## Transport and Identity

Kith {{KITH}} binds its HTTPS listener exclusively to a Tailscale
{{TAILSCALE}} overlay network interface.  It calls the Tailscale
LocalAPI `/localapi/v0/whois` for each connection to obtain the
verified `UserProfile.ID` and `UserProfile.LoginName`, which map
to `userId` and `login` respectively.

## Capability URI

Kith advertises `urn:kith:chat:1`.  The data model and methods
are identical to this specification.  The distinct URI allows Kith
deployments to be identified in Session objects.

## Supported Feature Set (Phase 1)

The initial Kith release supports direct chats, delivery and read
receipts, attachments, and EventSource push.  Group chat, reactions,
editing, deletion, typing indicators, and presence are planned for
Phase 2.

## Contact Discovery

Contacts are created automatically on first `Peer/deliver` from an
unknown peer.  `serverUrl` is populated by probing the peer's
`/.well-known/jmap` endpoint at delivery time.

## Deployment Topology

One Kith daemon serves exactly one user.  There is no multi-tenant
mode.

# Acknowledgements

The author thanks the JMAP working group for {{RFC8620}}, which
provided the protocol foundation this capability is built upon.
