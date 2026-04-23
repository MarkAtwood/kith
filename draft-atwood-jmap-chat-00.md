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

informative:
  RFC8621:
  RFC9420:
  ULID:
    title: Universally Unique Lexicographically Sortable Identifier
    target: https://github.com/ulid/spec
    date: 2019
  KITH:
    title: Kith — tailnet-native chat
    target: https://github.com/MarkAtwood/kith
    date: 2026
  NIE:
    title: nie — encrypted relay chat
    target: https://github.com/MarkAtwood/nie
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
for each type; and five server-to-server methods (Peer/deliver,
Peer/receipt, Peer/typing, Peer/retract, Peer/groupUpdate) for
direct mailbox-to-mailbox communication.

The protocol covers the feature set common to contemporary messaging
systems: group chat with membership roles, message reactions, editing,
deletion, threading, @mentions, typing indicators, read receipts per
participant, presence, pinned messages, and per-chat notification
settings.

Note: `urn:jmap:chat:1` is a provisional capability URI used in this
document.  If this specification is adopted by the IETF JMAP working
group, the URI will be updated to `urn:ietf:params:jmap:chat`.

--- middle

# Introduction

JMAP {{RFC8620}} defines a JSON-based protocol for accessing and
mutating application data.  The core protocol is intentionally
generic; application semantics are expressed through capability URIs
declared in the JMAP Session object.  {{RFC8621}} defines JMAP for
Mail.  This document defines an analogous capability for real-time
chat.

This specification accommodates two primary deployment topologies.
In the **mailbox-per-user** model, each participant runs their own
JMAP server (a "mailbox") that stores only their own messages; there
is no central server, no central message store, and no central
operator; mailboxes exchange messages directly with each other over a
secure transport.  In the **relay** model, a shared server routes
messages between clients; the Peer/* server-to-server methods are
implemented by the relay rather than individual user-controlled
mailboxes.  In relay deployments the relay MUST handle only opaque
ciphertext — it MUST NOT have access to plaintext message content
(see {{e2ee}}).  Both topologies are fully compatible with this
specification; transport, identity, and encryption choices are
confined to the deployment layer.

Authentication is handled entirely at the transport layer.  The
protocol requires only that the authentication layer provide a stable,
opaque user identity string for each connection.  How that identity
is established — overlay network membership, mutual TLS, bearer
tokens, or any other mechanism — is outside the scope of this
document.

The reference implementation of this capability is Kith {{KITH}}.
Implementation-specific details are in {{impl-notes}}.

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

id / userId:
: A Contact's `id` is the stable, opaque identity string provided by
  the authentication layer for that user.  These two terms are
  intentionally equivalent in this protocol: Contact.id IS the
  userId.  There is no separate identity namespace.  Servers MUST
  set Contact.id to the userId string obtained from the
  authentication layer.

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
: Maximum number of members in a group chat, including the owner.

`supportedBodyTypes` (String[]):
: MIME types accepted in `bodyType`.  MUST include `"text/plain"`.
  End-to-end encrypted deployments SHOULD also include an appropriate
  encrypted-content type such as `"application/mls-ciphertext"`.

`supportsThreads` (Boolean):
: Whether this server supports the optional thread model defined in
  {{threads}}.

## Account-Level Capability Object

The value of `accountCapabilities["urn:jmap:chat:1"]` is a JSON
object with the following field:

`role` (String):
: Either `"owner"` or `"peer"`.

## Session Object Extensions

Servers MAY include in the Session object:

`ownerUserId` (String):
: The id of the mailbox owner (equals owner's Contact.id on any
  peer server that has recorded this mailbox as a contact).

`ownerLogin` (String):
: A human-readable login name for the mailbox owner.

`ownerDirectAddress` (String, optional):
: A deployment-specific address at which the owner's client may
  be reachable directly.  Peers that probe `/.well-known/jmap`
  SHOULD store this value as the `directAddress` on the
  corresponding Contact record.

# Data Types

## Contact

A Contact represents a remote user known to this mailbox.  A
Contact's `id` is exactly the userId provided by the authentication
layer: it is the single, global identity key for that user within
this deployment.

`id` (String, immutable, server-set):
: The userId provided by the authentication layer.  This is the
  stable, opaque identifier for this user everywhere in the
  protocol.  Servers MUST set this to the verified identity string
  and MUST NOT assign a different value.

`login` (String, server-set):
: Human-readable login name.  MUST NOT be empty.  Typically
  email-shaped, but format is deployment-specific.

`displayName` (String, optional):
: Human-readable display name.  MAY be absent or empty.  Clients
  SHOULD fall back to `login`, then `id`.

`serverUrl` (String):
: Base HTTPS URL of this contact's mailbox.  Used for outbound
  delivery and for probing `/.well-known/jmap`.

`firstSeenAt` (UTCDate, server-set):
: Time this contact was first recorded.

`lastSeenAt` (UTCDate, server-set):
: Time of most recent interaction with this contact's mailbox.

`presence` (String, server-set):
: Last known presence state: `"online"`, `"away"`, `"offline"`, or
  `"unknown"`.  Updated on a best-effort basis.

`lastActiveAt` (UTCDate, optional, server-set):
: Time the contact was last observed to be active.

`directAddress` (String, optional):
: A deployment-specific address at which this contact's client may
  be reachable directly, without routing through their mailbox.
  The format and semantics are deployment-defined (examples:
  a Tailscale node name, a WebRTC signaling URI, an IP:port).
  This field is a hint only: senders MAY attempt delivery to this
  address when both parties are online and the deployment supports
  it, but MUST fall back to the standard mailbox path on any
  failure.  This field has no effect on message storage or
  multi-device sync; those remain the responsibility of the
  mailbox.  Servers populate this field from the `ownerDirectAddress`
  advertised in the contact's `/.well-known/jmap` Session object.

`blocked` (Boolean):
: When `true`, messages from this contact are silently dropped by
  this mailbox, including messages arriving in group chats.
  Default: `false`.

## ChatMember

A ChatMember describes one participant in a group Chat.  The `id`
field is the participant's Contact.id (which equals their userId).

`id` (String):
: The participant's Contact.id / userId.

`role` (String):
: Either `"admin"` or `"member"`.  Admins may add and remove
  members and update group chat metadata.  The creator is
  automatically assigned the `"admin"` role.

`joinedAt` (UTCDate):
: Time this participant joined the chat.

`invitedBy` (String, optional):
: The Contact.id of the member who added this participant.

## Chat

A Chat is a conversation between two or more participants.  Direct
chats (kind `"direct"`) and group chats (kind `"group"`) have
different identity schemes, described below.

### Chat ID Assignment {#chat-id}

All Chat IDs — both direct and group — are ULIDs {{ULID}} assigned
by the creating server at the moment the chat is created.  IDs are
opaque; they do not encode participants.  Chat IDs are stable for
the lifetime of the chat.

For a direct chat, the creating server is the one whose owner sends
the first message.  Before assigning a new chatId, the server MUST
check whether a direct chat with the relevant contactId already
exists locally (e.g., established via a prior `Peer/deliver` from
that contact).  If one exists, the server MUST use the existing
chatId rather than creating a new one.

When a `Peer/deliver` arrives for a direct chat with a chatId the
receiving server has not seen before, the receiving server creates a
new Chat record with that chatId and `contactId` set to the sender.

For group chats, the creating server distributes the chatId to all
initial members via `Peer/groupUpdate` ({{peer-groupupdate}}) before
any messages are sent.

### Chat Object Fields

`id` (String, immutable, server-set):
: A ULID assigned by the creating server per {{chat-id}}.

`kind` (String, immutable):
: `"direct"` or `"group"`.

`contactId` (String, immutable):
: **Direct chats only.**  The Contact.id of the other participant.

`name` (String):
: **Group chats only.**  Display name of the group.  Required at
  creation.  Mutable by admins.

`description` (String, optional):
: **Group chats only.**  Short description.  Mutable by admins.

`avatarBlobId` (String, optional):
: **Group chats only.**  blobId of the group avatar image.
  Mutable by admins.

`members` (ChatMember[]):
: **Group chats only.**  Full membership list including the owner.

`createdAt` (UTCDate, immutable, server-set):
: Time this chat was first recorded on this mailbox.

`lastMessageAt` (UTCDate, optional, server-set):
: Received time of the most recent message.

`unreadCount` (UnsignedInt, server-set):
: Messages received since the owner last read this chat.

`pinnedMessageIds` (String[]):
: Ordered list of pinned Message ids, most-recently-pinned first.
  For group chats, only admins may modify this list.  For direct
  chats, the owner may modify it freely.  Empty by default.

`muted` (Boolean):
: When `true`, push notifications for this chat are suppressed.
  Owner-side preference; not shared with peers.  Default: `false`.

`muteUntil` (UTCDate, optional):
: Muting expires at this time.  Servers SHOULD clear `muted` and
  `muteUntil` automatically when the time passes.

`messageExpirySeconds` (UnsignedInt, optional):
: A local expiry policy.  When set and non-zero, messages in this
  chat older than this many seconds are deleted by this mailbox.
  Each mailbox enforces its own policy independently.  This is a
  local setting, not a bilateral negotiated commitment: the peer
  is under no obligation to apply the same value.

## Reaction

A Reaction is an emoji response to a Message.

`emoji` (String):
: The reaction emoji.  Implementations SHOULD limit this to a
  single grapheme cluster.

`senderId` (String):
: `"self"` for the owner's reaction, or a Contact.id.

`sentAt` (UTCDate):
: Time the reaction was added.

## Mention

A Mention identifies a user referenced within a message body.

`id` (String):
: The Contact.id (userId) of the mentioned participant.

`offset` (UnsignedInt):
: Byte offset into `body` where the mention text begins.

`length` (UnsignedInt):
: Byte length of the mention text.  Servers MUST reject a mention
  where `offset + length` exceeds the byte length of `body`.

## MessageRevision

A MessageRevision records one historical version of a Message body.

`body` (String):
: The prior body text.

`bodyType` (String):
: The prior MIME type.

`editedAt` (UTCDate):
: The time this version was superseded by an edit.

## Message

A Message is a single transmission within a Chat.

### Message IDs

Message IDs are ULIDs {{ULID}}, assigned by the receiving mailbox at
storage time.  ULIDs are lexicographically ordered by time, enabling
ordered retrieval without a separate sort field.

Separately, the **sender-assigned ULID** (`senderMsgId`) is set by
the originating mailbox and carried in `Peer/deliver`.  The receiving
mailbox stores both its own `id` (the receiver-assigned ULID) and
the `senderMsgId`.  Servers MUST index stored messages by
`senderMsgId` within each chat to support idempotent delivery and
`Peer/retract` lookup.  If a `senderMsgId` is seen again for the
same chat, the server MAY silently discard the duplicate.

### Message Object Fields

`id` (String, immutable, server-set):
: Receiver-assigned ULID.  Used in all client-facing references.

`senderMsgId` (String, immutable, server-set):
: The sender-assigned ULID carried in `Peer/deliver`.  Equals `id`
  for messages composed by the owner.

`chatId` (String, immutable):
: ID of the containing Chat.

`senderId` (String, immutable, server-set):
: `"self"` for owner-composed messages; the sender's Contact.id for
  inbound messages, as verified by the authentication layer.

`body` (String):
: Message content.  When `bodyType` is `"text/plain"` or another
  plaintext type, body MUST be valid UTF-8 text.  When `bodyType`
  indicates an end-to-end encrypted payload (e.g.,
  `"application/mls-ciphertext"`), body contains ciphertext encoded
  as a base64url string; servers MUST store and forward it without
  inspection or transformation.  Cleared to empty string when the
  message is deleted.

`bodyType` (String):
: MIME type of `body`.  MUST be in `supportedBodyTypes`.

`attachments` (Attachment[]):
: File attachments.  Cleared to empty array when deleted.

`mentions` (Mention[]):
: Structured @mention annotations.  Empty by default.

`reactions` (Reaction[]):
: Emoji reactions.  Empty by default.

`replyTo` (String, optional):
: The receiver-assigned `id` of the Message this replies to.
  Servers MUST validate this ID exists in the same Chat.

`threadRootId` (String, optional):
: The receiver-assigned `id` of the thread root message.  Only
  meaningful when `supportsThreads` is `true`.  See {{threads}}.

`replyCount` (UnsignedInt, server-set):
: Count of messages in this chat with `replyTo` equal to this
  message's `id`.  Present only when `supportsThreads` is `true`.

`sentAt` (UTCDate):
: Sender's claimed composition time.  Peer-supplied; MUST be
  treated as untrusted.  MUST NOT be used for ordering.

`receivedAt` (UTCDate, immutable, server-set):
: Time this mailbox stored the message.  Authoritative for ordering
  and expiry calculations.

`senderExpiresAt` (UTCDate, optional, immutable):
: Sender-set hard-deletion deadline.  When present, servers MUST
  permanently delete this message — removing the row entirely, not
  leaving a tombstone — at or before this time.  A hard-deleted
  message appears in the `destroyed` list of subsequent
  `Message/changes` responses, not `updated`.  Receiving servers
  MUST honor this field regardless of local `messageExpirySeconds`
  policy; whichever deadline arrives first takes effect.  Servers
  MUST NOT use this field for message ordering.

`burnOnRead` (Boolean, optional, immutable):
: When `true`, the receiving server MUST permanently delete (hard-
  delete, as above) this message immediately after setting `readAt`.
  Applies only to the receiving mailbox; the sender's own copy is
  not affected.  In E2EE relay deployments the relay cannot observe
  read events; the bridge or client layer MUST enforce this rule
  after receiving the read acknowledgement from the owner.

`deliveryState` (String, server-set):
: `"pending"`, `"delivered"`, `"failed"`, or `"received"`.  For
  group chats, reflects aggregate state across all recipients; see
  `deliveryReceipts` for per-recipient detail.

`deliveryReceipts` (Object, optional, server-set):
: For group chats, a JSON object mapping each non-owner participant's
  Contact.id to `{"deliveredAt": <UTCDate-or-null>, "readAt":
  <UTCDate-or-null>}`.  Present only when `senderId` is `"self"`.

`deliveredAt` (UTCDate, optional, server-set):
: Time the first outbound delivery was acknowledged.

`readAt` (UTCDate, optional, server-set):
: Time the owner acknowledged reading this message.

`editedAt` (UTCDate, optional, server-set):
: Time of the most recent edit.

`editHistory` (MessageRevision[], optional, server-set):
: Prior versions, oldest first.  Servers MAY limit the number of
  retained revisions.

`deletedAt` (UTCDate, optional, server-set):
: Time the message was deleted.  When set, `body` is empty and
  `attachments` is empty.  The record is retained as a tombstone.

`deletedForAll` (Boolean, optional, server-set):
: `true` when deletion was propagated to all participants via
  `Peer/retract`.

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

Contacts are created automatically when a peer delivers a message or
a group update names a new participant.  Owner clients may not create
or destroy contacts.

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
: Contact.id of the other participant.  If a direct Chat with this
  contactId already exists, the server MUST return it in `updated`
  rather than creating a duplicate.  Otherwise the server assigns a
  new ULID as the chatId per {{chat-id}}.

#### Creating a Group Chat

`create` with `kind: "group"` accepts:

`name` (String, required):
: Display name of the group.

`memberIds` (String[], required):
: Contact.ids of initial non-owner members.  The server resolves
  these to Contact records, creating minimal records if necessary.
  Total membership including the owner MUST NOT exceed
  `maxGroupMembers`.

`description` (String, optional), `avatarBlobId` (String, optional),
`messageExpirySeconds` (UnsignedInt, optional).

The server assigns the group chat ID (a ULID), sets the owner as
an admin member, and MUST send `Peer/groupUpdate` to each initial
member before any messages are sent.

#### Updating a Chat

`update` supports: `muted`, `muteUntil`, `pinnedMessageIds`,
`messageExpirySeconds` (all chat kinds).

For group chats, admin role additionally allows: `name`,
`description`, `avatarBlobId`.

Member list changes use the following update patch keys:

`addMembers` (Object[]):
: Each entry: `id` (String, Contact.id) and optional `role`
  (String, default `"member"`).  Requires admin role.  Total
  membership after addition MUST NOT exceed `maxGroupMembers`.
  The server MUST send `Peer/groupUpdate` to all current members.

`removeMembers` (String[]):
: Contact.ids to remove.  Requires admin role.  The server MUST
  send `Peer/groupUpdate` to all remaining members and to the
  removed members.

`updateMemberRoles` (Object[]):
: Each entry: `id` (String) and `role` (String).  Requires admin
  role.  The server MUST send `Peer/groupUpdate` to all members.

### Chat/changes

Standard JMAP `/changes`.

### Chat/query

Standard JMAP `/query`.

Filter properties: `kind` (String), `muted` (Boolean).
Default sort: `lastMessageAt` descending; chats without messages
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
`threadRootId` (String, optional), `senderExpiresAt` (UTCDate,
optional), `burnOnRead` (Boolean, optional).

The server sets `id`, `senderMsgId`, `senderId`, `receivedAt`,
`deliveryState`, and delivery timestamp fields, then enqueues
the message for outbound delivery.

#### Editing a Message

`update` with changed `body`, `bodyType`, and/or `mentions`, on a
message where `senderId` is `"self"` and `deletedAt` is absent.

The server MUST:

1. Push a MessageRevision onto `editHistory` with the current
   `body`, `bodyType`, and timestamp as `editedAt`.
2. Replace `body` and `bodyType` with the submitted values.
3. Set `editedAt` to the current server time.
4. Send `Peer/deliver` carrying an `edit` payload to all
   recipients (see {{peer-deliver}}).

#### Adding and Removing Reactions

`update` with `addReaction` or `removeReaction`:

`addReaction` (Object):
: `{"emoji": <String>}`.  Server appends a Reaction with
  `senderId: "self"` and current time.  Servers SHOULD enforce a
  per-message per-sender reaction limit.  Server MUST propagate
  via `Peer/deliver` `reactionUpdate` payload.

`removeReaction` (Object):
: `{"emoji": <String>}`.  Removes the owner's matching reaction.
  Server MUST propagate via `Peer/deliver` `reactionUpdate` payload.

#### Deleting a Message

`update` with `deletedAt: <timestamp>`.

- If `deletedForAll: true` is also set, the server MUST send
  `Peer/retract` to all participants before marking the local
  record.  Servers MUST reject `deletedForAll: true` for messages
  where `senderId` is not `"self"`.
- Otherwise, deletion is local only: `body` and `attachments` are
  cleared on this mailbox with no peer notification.

#### Marking as Read

`update` with `readAt: <UTCDate>`.

### Message/changes

Standard JMAP `/changes`.

### Message/query

Standard JMAP `/query`.

All requests MUST include a `chatId` filter.

Additional filter properties:

`text` (String, optional):
: Full-text search over `body`.  Servers that do not support
  full-text search MUST return `unsupportedFilter`.

`threadRootId` (String, optional):
: Return only messages in this thread.  Valid only when
  `supportsThreads` is `true`; otherwise servers MUST return
  `unsupportedFilter`.

`hasAttachment` (Boolean, optional):
: Filter to messages with or without attachments.

`hasMention` (Boolean, optional):
: Filter to messages that mention the owner (owner's Contact.id
  appears in `mentions`).

Default sort: `receivedAt` ascending.

### Message/queryChanges

Standard JMAP `/queryChanges` ({{RFC8620}} Section 5.6).

# Optional: Thread Model {#threads}

Servers advertising `supportsThreads: true` support structured
conversation threads.

A thread is the set of Messages sharing a common `threadRootId`.
The root message has `threadRootId` absent.

Thread root assignment rules:

- A message with no `replyTo`: it is a potential thread root.
  `threadRootId` MUST be absent.
- A message replying to a thread root (the referenced message has
  no `threadRootId`): set `threadRootId` to `replyTo`.
- A message replying to a non-root message: set `threadRootId` to
  the referenced message's `threadRootId`.

Clients MUST follow these rules.  Servers SHOULD validate them and
MAY correct `threadRootId` if the client supplies an incorrect value.

`Message/query` with a `threadRootId` filter returns all messages in
that thread.  `replyCount` on each message gives the count of direct
replies.

# Server-to-Server Methods {#peer-methods}

The following methods are used between mailbox servers only.  Callers
without the `"peer"` role MUST receive `forbiddenMethod`.

## Peer/deliver {#peer-deliver}

Delivers a new message, an edit, or a reaction update from a remote
mailbox.  Exactly one of `message`, `edit`, or `reactionUpdate` MUST
be present.

Method name: `Peer/deliver`

Request arguments:

`accountId` (String):
: Account ID on the receiving server.

`chatId` (String):
: The Chat ID.  For direct chats, if the receiving server already
  has a chat with this contactId, it MUST verify that `chatId`
  matches the stored chatId.  For group chats, the receiver MUST
  verify this value matches the chatId of a known group of which
  the sender is a current member.

`senderUserId` (String):
: The sender's id (Contact.id / userId).  MUST match the identity
  provided by the authentication layer.  The receiver MUST compare
  these and MUST reject the request if they differ.

`chatKind` (String):
: `"direct"` or `"group"`.  Informs which chatId verification
  procedure applies.

`message` (Object, optional):
: A new message to deliver.  All peer-supplied fields:

  - `senderMsgId` (String) — Sender-assigned ULID.  Idempotency key.
  - `body` (String) — Validated against `maxBodyBytes`.
  - `bodyType` (String) — Validated against `supportedBodyTypes`.
  - `sentAt` (UTCDate) — Stored as-is; not used for ordering.
  - `attachments` (Object[]) — Each carries Attachment fields plus
    `fetchUrl` (String): the URL from which the receiver fetches the
    blob.
  - `mentions` (Mention[], optional).
  - `replyTo` (String, optional) — Sender's own `senderMsgId` of
    the referenced message.  Receiver resolves to local `id` via the
    `senderMsgId` index.
  - `threadRootId` (String, optional) — Sender's own `senderMsgId`
    of the thread root.  Receiver resolves similarly.
  - `senderExpiresAt` (UTCDate, optional) — Hard-deletion deadline.
    Receivers MUST honor this value.  Servers MUST reject a value
    that is already in the past at delivery time with
    `invalidArguments`.
  - `burnOnRead` (Boolean, optional) — Hard-delete on first read.

`edit` (Object, optional):
: An edit to an existing message.  Fields:

  - `senderMsgId` (String) — Identifies the message to edit via
    the `senderMsgId` index.
  - `body` (String) — New body; validated against `maxBodyBytes`.
  - `bodyType` (String) — Validated against `supportedBodyTypes`.
  - `editedAt` (UTCDate) — Claimed edit time; stored as-is.
  - `mentions` (Mention[], optional).

  The receiver MUST verify the sender is the original sender of the
  identified message before applying the edit.

`reactionUpdate` (Object, optional):
: A reaction change on an existing message.  Fields:

  - `senderMsgId` (String) — Identifies the target message.
  - `emoji` (String) — The reaction emoji.
  - `action` (String) — `"add"` or `"remove"`.
  - `sentAt` (UTCDate).

### New Message Validation

Before storing a new message, the server MUST in order:

1. Verify caller identity via authentication layer.
2. Confirm `senderUserId` matches the verified identity.
3. For direct chats: if a chat with this sender already exists,
   confirm `chatId` matches its stored id; otherwise create a new
   Chat record with this chatId and contactId.  For group chats:
   confirm `chatId` matches a known group and the sender is a
   current member.
4. Confirm the sender is not blocked by the owner.
5. Validate `body` byte length against `maxBodyBytes`.  For
   plaintext `bodyType` values, also validate UTF-8 encoding.  For
   encrypted `bodyType` values (e.g.,
   `"application/mls-ciphertext"`), body is opaque; servers MUST
   NOT parse or transform it beyond byte-length checking.
6. Validate `bodyType` against `supportedBodyTypes`.
7. Validate each attachment `filename`, `contentType`, `size`.
8. Fetch each attachment blob from `fetchUrl`; verify byte count
   against `size` and content against `sha256`.
9. Validate each mention `offset + length` against body length.
10. If `senderExpiresAt` is present, confirm it is strictly in the
    future; reject with `invalidArguments` if not.  Schedule
    hard deletion at that time.  If `burnOnRead` is `true`,
    register a trigger to hard-delete the message when `readAt`
    is set.

Failure at any step MUST result in rejection with no data stored.

### Edit and Reaction Validation

For `edit` payloads: apply steps 1–4 above, then validate `body`
and `bodyType` as in steps 5–6, then verify the identified message
exists and `senderUserId` matches its recorded sender.

For `reactionUpdate` payloads: apply steps 1–4, validate `emoji`
as a non-empty string, verify the identified message exists.

Response arguments:

`accountId` (String), `receivedMsgId` (String — the receiver's
assigned ULID for a new message, or the local `id` of the edited
or reacted-to message), `receivedAt` (UTCDate).

## Peer/receipt

Notifies the sending mailbox that a message was stored and/or read.

Method name: `Peer/receipt`

Request: `accountId` (String), `senderMsgId` (String — the
sender-assigned ULID), `deliveredAt` (UTCDate, optional — time of
storage), `readAt` (UTCDate, optional — time the recipient read the
message), `readerUserId` (String — the Contact.id of the
acknowledging user, for group receipt aggregation).

Response: `accountId`.

## Peer/typing

Notifies a remote mailbox that the owner is or is not typing.

Method name: `Peer/typing`

Request: `accountId` (String), `chatId` (String), `senderUserId`
(String, MUST match authenticated identity), `typing` (Boolean).

Response: `accountId`.

The receiving server MUST NOT store this event.  It MUST forward a
`typing` push event ({{push}}) to the owner's connected clients.
Servers MUST rate-limit inbound `Peer/typing` calls per peer.

## Peer/retract

Requests that a remote mailbox tombstone a specific message.

Method name: `Peer/retract`

Request: `accountId` (String), `chatId` (String), `senderUserId`
(String, MUST match authenticated identity), `senderMsgId` (String
— the sender-assigned ULID of the message to retract).

The receiving server MUST look up the message by `senderMsgId`
within `chatId`.  It MUST verify that the stored message's
`senderId` matches `senderUserId` before applying the tombstone.
On success, `body` and `attachments` are cleared, `deletedAt` is
set to the current time, and `deletedForAll` is set to `true`.

Response: `accountId`, `retractedAt` (UTCDate).

## Peer/groupUpdate {#peer-groupupdate}

Notifies participant mailboxes of a new group chat or a membership /
metadata change to an existing one.

Method name: `Peer/groupUpdate`

Request arguments:

`accountId` (String), `chatId` (String — the group chat ULID),
`senderUserId` (String, MUST match authenticated identity and MUST
be an admin of the group on the sending server).

`action` (String):
: One of:
  - `"create"` — Initial group creation notification.  Carries the
    full initial state.
  - `"addMembers"` — Members were added.
  - `"removeMembers"` — Members were removed.
  - `"updateRoles"` — Member roles changed.
  - `"updateMetadata"` — `name`, `description`, or `avatarBlobId`
    changed.

`members` (ChatMember[], required for `"create"`):
: Full membership list at the time of this update.

`addedMembers` (ChatMember[], for `"addMembers"`):
: Newly added members.

`removedMemberIds` (String[], for `"removeMembers"`):
: Contact.ids of removed members.

`updatedRoles` (Object[], for `"updateRoles"`):
: Each entry: `id` (String), `role` (String).

`name` (String, optional), `description` (String, optional),
`avatarBlobId` (String, optional):
: Updated metadata fields (any combination, for `"updateMetadata"`
  or `"create"`).

The receiving server MUST verify `senderUserId` is authenticated
and is an admin of this group (or, for `"create"`, is the initial
creator).  On success, the receiving server updates its local Chat
record accordingly.

Response: `accountId`.

# Push Notifications {#push}

Servers MUST support the EventSource mechanism defined in
{{RFC8620}} Section 7.3.

## State-Change Events

~~~
event: state
data: {"changed":{"<accountId>":{"Message":"<s>","Chat":"<s>","Contact":"<s>"}}}
~~~

Clients SHOULD call the corresponding `/changes` method.  On
`cannotCalculateChanges`, fall back to `/get`.

## Typing Events

~~~
event: typing
data: {"chatId":"<id>","senderId":"<contact-id>","typing":<bool>}
~~~

Not stored; carries no state token.

## Presence Events

~~~
event: presence
data: {"contactId":"<id>","presence":"<state>","lastActiveAt":"<ts>"}
~~~

# Blob Storage

Standard JMAP blob upload and download per {{RFC8620}} Section 6,
using the `uploadUrl` and `downloadUrl` Session templates.

## Upload

`POST <uploadUrl>` with the blob as the request body.

Response (HTTP 200) — this document extends the standard RFC 8620
upload response with the `sha256` field:

~~~json
{
  "blobId":  "<id>",
  "type":    "<mime-type>",
  "size":    <bytes>,
  "sha256":  "<lowercase-hex>"
}
~~~

## Download

`GET <downloadUrl>` with placeholders percent-encoded.

# Outbox and Delivery

Outbound messages MUST be queued in a persistent outbox before the
first delivery attempt.  Servers MUST retry with exponential backoff.

For group chats, the sender delivers independently to each
participant's mailbox and tracks per-recipient state in
`deliveryReceipts`.  The aggregate `deliveryState` advances to
`"delivered"` when all participants have acknowledged.

A message whose `senderMsgId` is already known for the given chat
MAY be silently discarded by the receiver.

Servers MUST maintain a durable index of `senderMsgId` values per
chat to support idempotent delivery, `Peer/retract` lookup, and
resolution of `replyTo` / `threadRootId` references in inbound
`Peer/deliver` messages.

# Authentication

Authentication is outside the scope of this document.  The protocol
requires a stable, opaque id per connection.

Access control:

- **Owner** (identity equals owner's id): all methods.
- **Peer** (identity equals a known contact's id): `Peer/deliver`,
  `Peer/receipt`, `Peer/typing`, `Peer/retract`,
  `Peer/groupUpdate` only.
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

Note: this URI is provisional.  If this specification is adopted by
the IETF JMAP working group, it will be updated to
`urn:ietf:params:jmap:chat`.

# Security Considerations {#security}

## Identity Verification Ordering

`senderUserId` in all Peer/* methods is caller-supplied and MUST be
treated as untrusted.  The server MUST obtain the verified identity
from its own authentication layer independently and MUST compare
before any storage or action.  Verification MUST precede all effects.

## Input Validation

All peer-supplied fields are attacker-controlled:

- `body`: validate UTF-8; enforce `maxBodyBytes`.
- `bodyType`: validate against `supportedBodyTypes`.
- `filename`: reject values containing `/`, `\`, or null bytes.
- `contentType`: reject syntactically invalid MIME values.
- `size`: verify against actual blob byte count after fetch.
- `sha256`: verify against actual blob content after fetch.
- `sentAt`, `editedAt`: store as-is; never use for ordering.
- `chatId`: recompute (direct) or verify membership (group);
  reject mismatches.
- `emoji`: enforce reasonable grapheme cluster length; enforce a
  per-message per-sender reaction limit.
- `mentions`: reject any entry where `offset + length` exceeds
  body byte length.

## Blob Fetch and SSRF

When fetching attachment blobs from peer-supplied `fetchUrl` values,
servers MUST restrict outbound connections to the known peer address
space.  Unrestricted fetches are an SSRF vector.

## Denial of Service

Enforce `maxBodyBytes` and `maxAttachmentBytes` at parse time, before
any fetch or storage.  Enforce `maxAttachmentsPerMessage` and
`maxGroupMembers` at creation and update time.  Rate-limit
`Peer/typing` per peer.

## Timestamp Trust

`sentAt` and peer-supplied `editedAt` are untrusted.  `receivedAt`
is server-set and is the authoritative timestamp for ordering and
expiry.

## Chat ID Integrity

Chat IDs are server-assigned ULIDs.  Security against
cross-conversation injection relies on sender authentication and
chat/membership verification, not on ID derivation.

For direct chats, the receiving server MUST confirm that the
incoming chatId matches the chatId already associated with the
sending contact (if one exists).  This prevents a sender from
injecting messages into a chat ID that belongs to a different
conversation.

For group chats, servers MUST confirm the sender is a current member
of the identified group before accepting any `Peer/deliver` or
`Peer/groupUpdate`.

## Retract Authorization

`Peer/retract` MUST verify via the `senderMsgId` index that
`senderUserId` matches the original sender before applying any
tombstone.

## Group Admin Verification

`Peer/groupUpdate` MUST verify that `senderUserId` holds an admin
role in the named group on the receiving server's local record before
applying membership or metadata changes.

## Direct Address Hints

`directAddress` and `ownerDirectAddress` are peer-supplied values
and MUST be treated as untrusted.  Implementations that use them
MUST apply the same authentication requirements to the direct path
as to the mailbox path, and MUST NOT use them as fetch targets in
contexts analogous to the blob-fetch SSRF risk described above.
Senders MUST NOT treat delivery to a `directAddress` as a
substitute for mailbox delivery; the mailbox path MUST still be
used to ensure message persistence and multi-device visibility.

## Blocked Contacts in Groups

Messages from a blocked contact are silently dropped regardless of
whether they arrive in a direct chat or a group chat context.

## Sender-Controlled Expiry and Burn-on-Read

`senderExpiresAt` and `burnOnRead` are peer-supplied values and MUST
be treated accordingly:

- Servers MUST reject `senderExpiresAt` values that are in the past
  at delivery time; accepting stale expiry would result in immediate
  silent deletion, which is indistinguishable from message loss.
- Servers MUST NOT use `senderExpiresAt` for message ordering or
  any purpose other than scheduling deletion.
- Hard deletion MUST remove the message row entirely.  Retaining a
  tombstone (body cleared, row present) does not satisfy this
  requirement.
- After hard deletion, any stored attachment blobs referenced by
  the message SHOULD also be purged.
- `burnOnRead` applies only on the receiving mailbox.  The sender's
  own copy is subject to the sender's local policies, not to
  `burnOnRead`.
- In E2EE relay deployments, the relay cannot observe the owner's
  read events.  The bridge or client layer MUST enforce `burnOnRead`
  after the owner signals that the message has been read.

## End-to-End Encrypted Deployments {#e2ee}

In relay deployments, the relay routes Peer/* messages but MUST NOT
have access to plaintext message content.  Implementations MUST
ensure:

- The `body` field carries ciphertext only; plaintext MUST never be
  transmitted to the relay in an encrypted deployment.
- The relay is architecturally excluded from the encryption key
  schedule (e.g., by using MLS {{RFC9420}} or a similar protocol
  that does not involve the relay in key agreement).
- Servers MUST NOT reject or transform `body` based on content when
  `bodyType` indicates an encrypted type.
- Metadata visible to the relay — sender id, recipient id,
  timestamp, and body size — remains an information-leakage surface.
  Deployments requiring metadata privacy SHOULD apply message
  padding and cover traffic at the transport layer; those techniques
  are outside the scope of this document.

--- back

# Implementation Notes: Kith {#impl-notes}

This appendix is informative.

## Transport and Identity

Kith {{KITH}} binds its HTTPS listener exclusively to a Tailscale
{{TAILSCALE}} overlay network interface.  For each connection, it
calls the Tailscale LocalAPI `/localapi/v0/whois` to obtain the
verified `UserProfile.ID`, which is used directly as the Contact.id
/ userId.  `UserProfile.LoginName` is stored as `login`.

## Capability URI

Kith advertises `urn:kith:chat:1`.  The data model and methods are
identical to this specification.  The distinct URI allows Kith
deployments to be identified in Session objects.

## Supported Feature Set

The initial Kith release (Phase 1) implements direct chats, delivery
and read receipts, attachments, and EventSource push.  Group chat,
reactions, editing, deletion, typing indicators, presence, and
Peer/groupUpdate are planned for Phase 2.

## Contact Discovery

Contacts are created automatically on first `Peer/deliver` from an
unknown peer.  `serverUrl` is populated by probing `/.well-known/jmap`
on the peer at delivery time.

## Deployment Topology

One Kith daemon serves exactly one user.  There is no multi-tenant
mode.

# Implementation Notes: nie {#impl-notes-nie}

This appendix is informative.

## Overview

nie (囁, "whisper") {{NIE}} is an end-to-end encrypted relay chat
system with privacy-coin subscription gating.  It provides a second
reference implementation of JMAP for Chat operating in the relay
topology described in the Introduction.

## Identity

nie users are identified by their Ed25519 public key (base64url-
encoded, 44 characters), with no account registration, email address,
or KYC.  This key serves as the Contact.id in the JMAP layer — a
stable, opaque identity string whose format is deployment-defined.

## Transport and Relay Topology

nie-relay is an axum-based WebSocket relay that routes encrypted
envelopes between authenticated public keys.  It stores only opaque
ciphertext; plaintext never reaches the server.  Authentication is
challenge-response: the relay issues a nonce; the client signs it
with their Ed25519 private key and returns the signature.

`nie-bridge-jmap` (included in the nie workspace) presents a JMAP
Chat interface in front of a nie-relay connection.  Owner methods
(`Contact/get`, `Chat/get`, `Message/get`, `Message/set`, etc.) are
served from a local SQLite store maintained by the bridge.  Peer/*
methods are translated to nie-relay WebSocket messages and back.

## End-to-End Encryption

Message payloads are encrypted using MLS (Messaging Layer Security,
{{RFC9420}}) via the `openmls` Rust crate.  The relay sees only:
sender public key, recipient public key, blob size, and timestamp.
The relay is architecturally excluded from the MLS key schedule.

In the JMAP Chat wire format, `body` carries the MLS ciphertext
encoded as a base64url string and `bodyType` is set to
`"application/mls-ciphertext"`.  The relay stores and forwards
this field without inspection per {{e2ee}}.

## Subscription Gating

Access to nie-relay is gated by subscription payment in privacy-
preserving cryptocurrencies (Zcash, Monero).  The relay accepts
payment to a per-invoice address, monitors the blockchain for
confirmation, and grants access to the corresponding public key.
No identity is required beyond the public key and proof of payment.
User-to-user payments are negotiated inside end-to-end encrypted
messages; the relay cannot distinguish payment negotiation from
ordinary chat traffic.

## Supported Feature Set

The initial nie release implements direct messaging, MLS-encrypted
payloads, and subscription gating.  Group chat, reactions, editing,
and the full JMAP Chat method set are planned for subsequent releases.

# Acknowledgements

The author thanks the JMAP working group for {{RFC8620}}.
