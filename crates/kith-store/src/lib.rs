pub mod attachment;
pub mod chat;
pub mod contact;
pub mod message;
pub mod outbox;
mod util;

use kith_core::{Attachment, DeliveryState, KithError, StateChange};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use tokio::sync::broadcast;

/// Metadata returned when a blob belongs to a message from a known peer contact.
///
/// The `mailbox_host` field identifies where to fetch the blob from; the
/// remaining fields are the attachment metadata as recorded at delivery time.
pub struct PeerBlobInfo {
    pub mailbox_host: String,
    pub filename: String,
    pub content_type: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Parameters for [`Store::insert_outbound_message`].
///
/// Using a struct instead of positional arguments makes call sites
/// self-documenting and allows new fields to be added without changing
/// every call site.
pub struct OutboundMessageParams<'a> {
    pub id: &'a str,
    pub chat_id: &'a str,
    pub body: &'a str,
    pub body_type: &'a str,
    pub sent_at_peer: Option<&'a str>,
    pub created_at_unix: i64,
    pub reply_to: Option<&'a str>,
    pub attachments: &'a [Attachment],
    /// `(peer_user_id, peer_mailbox_host)` pairs.  Must be non-empty.
    pub outbox_peers: &'a [(&'a str, &'a str)],
}

/// Wraps a rusqlite connection and owns the database handle for this mailbox.
pub struct Store {
    pub(crate) conn: Connection,
    /// Optional channel for broadcasting state-change notifications.
    ///
    /// `None` until the daemon calls `set_events_tx` after construction.
    /// Sub-stores receive a reference to this field and call `send` after
    /// any write that advances a JMAP state counter.
    pub events_tx: Option<broadcast::Sender<StateChange>>,
}

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS self (
    tailscale_user_id TEXT NOT NULL PRIMARY KEY,
    tailscale_login   TEXT NOT NULL,
    display_name      TEXT,
    created_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    peer_user_id      TEXT NOT NULL PRIMARY KEY,
    peer_login        TEXT NOT NULL,
    peer_mailbox_host TEXT NOT NULL,
    display_name      TEXT,
    first_seen_at     INTEGER NOT NULL,
    last_seen_at      INTEGER NOT NULL,
    blocked           INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS chats (
    id              TEXT NOT NULL PRIMARY KEY,
    kind            TEXT NOT NULL DEFAULT 'direct',
    created_at      INTEGER NOT NULL,
    last_message_at INTEGER
);

CREATE TABLE IF NOT EXISTS chat_members (
    chat_id      TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    peer_user_id TEXT NOT NULL,
    PRIMARY KEY (chat_id, peer_user_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id               TEXT NOT NULL PRIMARY KEY,
    chat_id          TEXT NOT NULL REFERENCES chats(id),
    sender_user_id   TEXT NOT NULL,
    body             TEXT NOT NULL,
    body_type        TEXT NOT NULL DEFAULT 'text/plain',
    sent_at_peer     TEXT,
    created_at       INTEGER NOT NULL,
    state_version    INTEGER NOT NULL DEFAULT 0,
    delivery_state   TEXT NOT NULL DEFAULT 'pending'
                         CHECK(delivery_state IN ('pending','delivered','failed','received')),
    delivered_at     INTEGER,
    read_at          INTEGER,
    reply_to         TEXT REFERENCES messages(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    message_id        TEXT NOT NULL PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    peer_user_id      TEXT NOT NULL,
    peer_mailbox_host TEXT NOT NULL,
    next_attempt_at   INTEGER NOT NULL,
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT
);

CREATE TABLE IF NOT EXISTS attachments (
    id           TEXT NOT NULL PRIMARY KEY,
    message_id   TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS state_counters (
    type_name TEXT NOT NULL PRIMARY KEY,
    counter   INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO state_counters (type_name, counter) VALUES
    ('contact', 0),
    ('chat',    0),
    ('message', 0);

CREATE INDEX IF NOT EXISTS messages_chat_time
    ON messages(chat_id, created_at);

CREATE INDEX IF NOT EXISTS messages_pending
    ON messages(delivery_state)
    WHERE delivery_state = 'pending';

CREATE INDEX IF NOT EXISTS outbox_next
    ON outbox(next_attempt_at);
";

const SCHEMA_V2: &str = "
CREATE INDEX IF NOT EXISTS messages_state_version
    ON messages(state_version);
";

const SCHEMA_V3: &str = "
CREATE TABLE outbox_v3 (
    message_id        TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    peer_user_id      TEXT NOT NULL,
    peer_mailbox_host TEXT NOT NULL,
    kind              TEXT NOT NULL DEFAULT 'message' CHECK(kind IN ('message', 'receipt')),
    read_at_unix      INTEGER,
    next_attempt_at   INTEGER NOT NULL,
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT,
    PRIMARY KEY (message_id, peer_user_id, kind)
);
INSERT INTO outbox_v3 (message_id, peer_user_id, peer_mailbox_host, kind, read_at_unix, next_attempt_at, attempt_count, last_error)
    SELECT message_id, peer_user_id, peer_mailbox_host, 'message', NULL, next_attempt_at, attempt_count, last_error
    FROM outbox;
DROP INDEX outbox_next;
DROP TABLE outbox;
ALTER TABLE outbox_v3 RENAME TO outbox;
CREATE INDEX outbox_next ON outbox(next_attempt_at);
";

// V4: add contact_id to chats (for direct-chat dedup via unique index),
//     add sender_msg_id to messages (for idempotent Peer/deliver).
const SCHEMA_V4: &str = "
ALTER TABLE chats ADD COLUMN contact_id TEXT;
UPDATE chats SET contact_id = (
    SELECT peer_user_id FROM chat_members WHERE chat_id = chats.id LIMIT 1
) WHERE kind = 'direct';
CREATE UNIQUE INDEX IF NOT EXISTS chats_direct_contact
    ON chats(contact_id) WHERE kind = 'direct';
ALTER TABLE messages ADD COLUMN sender_msg_id TEXT;
UPDATE messages SET sender_msg_id = id;
CREATE INDEX IF NOT EXISTS messages_sender_msg_id
    ON messages(chat_id, sender_msg_id);
";

// V5: replace the non-unique messages_sender_msg_id index (V4) with a UNIQUE
//     INDEX so the idempotency guarantee is enforced at the database level, not
//     only in application logic.  SQLite does not support upgrading a non-unique
//     index to UNIQUE in place; the old index must be dropped and recreated.
//
//     The dedup DELETE runs first to handle the (unlikely but possible) case
//     where a V4 database has duplicate (chat_id, sender_msg_id) rows from a
//     retransmission that landed while KITH-orvy.1 (error-swallowing idempotency
//     check) was present.  Without it, CREATE UNIQUE INDEX would fail on any
//     such database.  MIN(rowid) keeps the first-received row, which is the
//     canonical one.  Only non-NULL sender_msg_id rows are considered because
//     UNIQUE INDEX permits multiple NULLs and they should not be deduplicated.
const SCHEMA_V5: &str = "
DELETE FROM messages
WHERE sender_msg_id IS NOT NULL
  AND rowid NOT IN (
    SELECT MIN(rowid) FROM messages
    WHERE sender_msg_id IS NOT NULL
    GROUP BY chat_id, sender_msg_id
  );
DROP INDEX IF EXISTS messages_sender_msg_id;
CREATE UNIQUE INDEX messages_sender_msg_id
    ON messages(chat_id, sender_msg_id);
";

// V6: Enforce sender_msg_id NOT NULL at the DB level via a BEFORE INSERT trigger.
// SQLite does not support ALTER COLUMN to add NOT NULL after the fact, and both
// current insert paths already take &str (non-nullable in Rust).  The trigger
// provides a second layer of defense against raw SQL access or a future refactor
// that changes the parameter type to Option<&str> without updating this invariant.
const SCHEMA_V6: &str = "
CREATE TRIGGER IF NOT EXISTS messages_sender_msg_id_not_null
BEFORE INSERT ON messages
WHEN NEW.sender_msg_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'sender_msg_id must not be NULL');
END;
";

// V7: Add a partial index to accelerate the unread_count correlated subquery
// used in ChatStore::list(), get(), and find_direct_by_contact_id().
// The query filters on chat_id, delivery_state='received', and read_at IS NULL.
// messages_chat_time(chat_id, created_at) covers the chat_id seek but requires
// a full per-chat scan to filter delivery_state and read_at.  This partial index
// indexes only the rows that are both received and unread, allowing the planner
// to evaluate the correlated subquery with an index scan rather than a full scan.
const SCHEMA_V7: &str = "
CREATE INDEX IF NOT EXISTS messages_unread
    ON messages(chat_id)
    WHERE delivery_state = 'received' AND read_at IS NULL;
";

// V8: add changed_at_counter to contacts for per-row state tracking.
// This enables ChatContact/changes to return correct newState when maxChanges
// truncation occurs (RFC 8620 §5.6 paging correctness).  Existing rows are
// set to the current contact state counter so they appear in any diff from
// sinceState < current; new rows record the counter at upsert/set_blocked time.
const SCHEMA_V8: &str = "
ALTER TABLE contacts ADD COLUMN changed_at_counter INTEGER NOT NULL DEFAULT 0;
UPDATE contacts SET changed_at_counter = (
    SELECT counter FROM state_counters WHERE type_name = 'contact'
);
";

// V9: add changed_at_counter to chats for per-row state tracking.
// Mirrors the V8 migration for contacts.  Enables Chat/changes to compute a
// correct newState when maxChanges truncation occurs (RFC 8620 §5.6 paging).
// Existing rows are stamped with the current chat state counter so they appear
// in any diff from sinceState < current; new rows record the counter at create
// / update_last_message_at time.
const SCHEMA_V9: &str = "
ALTER TABLE chats ADD COLUMN changed_at_counter INTEGER NOT NULL DEFAULT 0;
UPDATE chats SET changed_at_counter = (
    SELECT COALESCE(counter, 0) FROM state_counters WHERE type_name = 'chat'
);
";

// V10: Add created_at_version to messages to distinguish RFC 8620 §5.2 created vs updated.
//
// created_at_version = state_version at the time of INSERT (never changes).
// state_version      = state_version at the time of last modification.
//
// A message where state_version > since AND created_at_version > since → "created".
// A message where state_version > since AND created_at_version <= since → "updated".
//
// Backfill: existing rows set created_at_version = state_version.  This is
// conservative — old messages may appear in "created" after upgrade if they were
// updated since insert, but no message is permanently lost from the change feed.
const SCHEMA_V10: &str = "
ALTER TABLE messages ADD COLUMN created_at_version INTEGER NOT NULL DEFAULT 0;
UPDATE messages SET created_at_version = state_version;
CREATE INDEX IF NOT EXISTS messages_created_at_version ON messages(created_at_version);
";

// V11: index on chats(changed_at_counter) so Chat/changes can use an index
// scan instead of a full table scan on `WHERE changed_at_counter > ?1 ORDER BY changed_at_counter`.
const SCHEMA_V11: &str = "
CREATE INDEX IF NOT EXISTS idx_chats_changed_at_counter ON chats(changed_at_counter);
";

// V12: index on contacts(changed_at_counter) — same optimization as V11 for chats.
// ChatContact/changes queries `WHERE changed_at_counter > ?1 ORDER BY changed_at_counter`;
// without this index the query does a full table scan of the contacts table.
const SCHEMA_V12: &str = "
CREATE INDEX IF NOT EXISTS idx_contacts_changed_at_counter ON contacts(changed_at_counter);
";

// V13: add created_at_counter to contacts so Contact/changes can distinguish
// newly-created contacts (RFC 8620 §5.2 created[]) from updated ones (updated[]).
// Mirrors the created_at_version column on messages.  Existing rows are backfilled
// to created_at_counter = changed_at_counter so they appear as "created" on a fresh
// sinceState=s-0 sync and as "updated" on any later sync.
const SCHEMA_V13: &str = "
ALTER TABLE contacts ADD COLUMN created_at_counter INTEGER NOT NULL DEFAULT 0;
UPDATE contacts SET created_at_counter = changed_at_counter WHERE changed_at_counter > 0;
";

// V14: Enforce singleton invariant on the 'self' table via a BEFORE INSERT trigger.
// The table may already have exactly one row (normal state), zero rows (fresh DB),
// or erroneously more than one row.  The trigger fires on any attempt to add a
// second row and raises an error.
const SCHEMA_V14: &str = "
CREATE TRIGGER IF NOT EXISTS self_singleton
    BEFORE INSERT ON self
    WHEN (SELECT COUNT(*) FROM self) > 0
BEGIN
    SELECT RAISE(ABORT, 'self table must contain exactly one row');
END;
";

// V15: Add indexes on contacts(peer_login) and messages(chat_id, state_version).
// contacts(peer_login) accelerates lookups by login name (e.g. WhoIs resolution).
// messages(chat_id, state_version) accelerates Message/changes queries that filter
// by chat and state counter range.
const SCHEMA_V15: &str = "
CREATE INDEX IF NOT EXISTS idx_contacts_peer_login ON contacts(peer_login);
CREATE INDEX IF NOT EXISTS idx_messages_chat_state ON messages(chat_id, state_version);
";

// V16: Recreate the messages table with ON DELETE CASCADE on the chat_id FK.
// SQLite does not support ALTER TABLE … DROP CONSTRAINT, so the standard
// table-recreation pattern is used.  All existing indexes and the V6 NOT NULL
// trigger are recreated on the new table.  PRAGMA foreign_keys is disabled
// only for the duration of this migration and re-enabled at the end.
const SCHEMA_V16: &str = "
PRAGMA foreign_keys = OFF;
CREATE TABLE messages_new (
    id               TEXT NOT NULL PRIMARY KEY,
    chat_id          TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_user_id   TEXT NOT NULL,
    body             TEXT NOT NULL,
    body_type        TEXT NOT NULL DEFAULT 'text/plain',
    sent_at_peer     TEXT,
    created_at       INTEGER NOT NULL,
    state_version    INTEGER NOT NULL DEFAULT 0,
    delivery_state   TEXT NOT NULL DEFAULT 'pending'
                         CHECK(delivery_state IN ('pending','delivered','failed','received')),
    delivered_at     INTEGER,
    read_at          INTEGER,
    reply_to         TEXT REFERENCES messages_new(id) ON DELETE SET NULL,
    sender_msg_id    TEXT,
    created_at_version INTEGER NOT NULL DEFAULT 0
);
INSERT INTO messages_new SELECT id,chat_id,sender_user_id,body,body_type,sent_at_peer,created_at,state_version,delivery_state,delivered_at,read_at,reply_to,sender_msg_id,created_at_version FROM messages;
DROP TABLE messages;
ALTER TABLE messages_new RENAME TO messages;
CREATE INDEX IF NOT EXISTS messages_chat_time ON messages(chat_id, created_at);
CREATE INDEX IF NOT EXISTS messages_pending ON messages(delivery_state) WHERE delivery_state = 'pending';
CREATE INDEX IF NOT EXISTS messages_state_version ON messages(state_version);
CREATE UNIQUE INDEX messages_sender_msg_id ON messages(chat_id, sender_msg_id);
CREATE INDEX IF NOT EXISTS messages_unread ON messages(chat_id) WHERE delivery_state = 'received' AND read_at IS NULL;
CREATE INDEX IF NOT EXISTS messages_created_at_version ON messages(created_at_version);
CREATE INDEX IF NOT EXISTS idx_messages_chat_state ON messages(chat_id, state_version);
CREATE TRIGGER IF NOT EXISTS messages_sender_msg_id_not_null
BEFORE INSERT ON messages
WHEN NEW.sender_msg_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'sender_msg_id must not be NULL');
END;
PRAGMA foreign_keys = ON;
";

// V17: Fix the created_at_counter sentinel for pre-V8 contacts.
//
// V13 backfilled created_at_counter = changed_at_counter WHERE changed_at_counter > 0.
// Contacts that existed before V8 (when changed_at_counter was added with DEFAULT 0)
// were left with created_at_counter = 0 after V13.  The upsert code uses 0 as the
// sentinel for "row was just inserted by this call", so the first upsert on such a
// contact incorrectly set created_at_counter = N and returned is_create = true,
// yielding a spurious Contact/changes created[] entry for an already-existing contact.
//
// Fix: mark those rows -1 ("pre-V8 uninitialized").  Upsert detects created_at < 0
// and sets created_at_counter = 0 (meaning "existed at or before state counter 0"),
// making is_create = (0 > sinceState) always false for any sinceState >= 0.
const SCHEMA_V17: &str = "
UPDATE contacts SET created_at_counter = -1 WHERE created_at_counter = 0;
";

// V18: add created_at_counter to chats so Chat/changes can distinguish newly-created
// chats from chats that were updated (e.g. last_message_at changed).  Without this
// column, get_changes_since_ordered cannot compute is_create and every chat change
// (including last_message_at updates) is incorrectly placed in created[] by
// ChatChangesHandler.
//
// V18 backfill was incorrect: it set created_at_counter = changed_at_counter for
// pre-existing chats.  A client whose sinceState predates those chats' last update
// would see them falsely appear in Chat/changes created[].  V19 fixes this.
const SCHEMA_V18: &str = "
ALTER TABLE chats ADD COLUMN created_at_counter INTEGER NOT NULL DEFAULT 0;
UPDATE chats SET created_at_counter = changed_at_counter WHERE changed_at_counter > 0;
";

// V19: Fix V18 backfill.  V18 set created_at_counter = changed_at_counter for
// pre-existing chats.  Because is_create = (created_at_counter > sinceCounter), a
// client at any sinceState before the last update would receive those chats in
// created[] — identical to the V13/V17 bug for contacts.
//
// Fix: reset to the -1 sentinel (same pattern as V17 for contacts).  -1 < 0 <=
// any valid sinceCounter, so is_create is always false for these rows.
//
// Edge case: chats created after V18 that have never received a message will also
// be reset to -1 (they have changed_at_counter = created_at_counter > 0).  Such
// chats appear in Chat/changes updated[] instead of created[] on the next sync,
// which is safe for any client that fetches unknown updated IDs.  New chats
// created after V19 are unaffected: create() stamps created_at_counter correctly.
const SCHEMA_V19: &str = "
UPDATE chats SET created_at_counter = -1 WHERE changed_at_counter > 0;
";

// MIGRATIONS must be sorted in ascending order by version number.
// Each entry is (target_user_version, sql). The runner applies all
// migrations whose target version exceeds the current PRAGMA user_version.
// Adding migrations out of order will silently skip them if
// user_version already exceeds their target.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, SCHEMA_V1),
    (2, SCHEMA_V2),
    (3, SCHEMA_V3),
    (4, SCHEMA_V4),
    (5, SCHEMA_V5),
    (6, SCHEMA_V6),
    (7, SCHEMA_V7),
    (8, SCHEMA_V8),
    (9, SCHEMA_V9),
    (10, SCHEMA_V10),
    (11, SCHEMA_V11),
    (12, SCHEMA_V12),
    (13, SCHEMA_V13),
    (14, SCHEMA_V14),
    (15, SCHEMA_V15),
    (16, SCHEMA_V16),
    (17, SCHEMA_V17),
    (18, SCHEMA_V18),
    (19, SCHEMA_V19),
];

impl Store {
    /// Open (or create) the database at `path`.
    pub fn open(path: &Path) -> Result<Self, KithError> {
        let conn = Connection::open(path).map_err(db_err)?;
        Self::init_conn(&conn)?;
        Self::migrate(&conn)?;
        Ok(Store {
            conn,
            events_tx: None,
        })
    }

    /// Open an in-memory database (used in tests).
    pub fn open_in_memory() -> Result<Self, KithError> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        Self::init_conn(&conn)?;
        Self::migrate(&conn)?;
        Ok(Store {
            conn,
            events_tx: None,
        })
    }

    /// Attach a broadcast sender so the store can emit `StateChange` events.
    ///
    /// Call this once after construction, before the daemon starts serving
    /// requests.  The sender is cheaply cloneable; all sub-stores share the
    /// same channel via the `Store` reference they already hold.
    pub fn set_events_tx(&mut self, tx: broadcast::Sender<StateChange>) {
        self.events_tx = Some(tx);
    }

    /// Configure connection-level PRAGMAs that must be set on every open.
    fn init_conn(conn: &Connection) -> Result<(), KithError> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
        )
        .map_err(db_err)
    }

    /// Apply any unapplied migrations, advancing `PRAGMA user_version` after each.
    fn migrate(conn: &Connection) -> Result<(), KithError> {
        let current: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(db_err)?;
        // `current` is intentionally read once before the loop.  Each migration
        // checks `current < version` against the snapshot taken at open time.
        // This is correct because migrations are strictly additive and ordered:
        // if migration N runs, every migration M < N also ran (either now or in
        // a previous open), so the stale snapshot never causes a skip.  The
        // single-writer guarantee means no concurrent writer can advance
        // user_version between iterations.
        //
        // Migrations listed here run without a wrapping transaction.  SQLite
        // silently ignores `PRAGMA foreign_keys` changes made inside a
        // multi-statement transaction (per SQLite docs), so any migration that
        // needs to toggle foreign_keys must run outside one.
        const RAW_MIGRATIONS: &[u32] = &[16];

        for &(version, sql) in MIGRATIONS {
            if current < version {
                if RAW_MIGRATIONS.contains(&version) {
                    // Run the SQL directly — no outer transaction.  The migration
                    // SQL is responsible for its own atomicity (e.g. via the
                    // implicit SQLite autocommit on each statement).
                    // PRAGMA user_version is set separately, also outside a
                    // transaction (PRAGMA writes are autocommitted).
                    conn.execute_batch(sql).map_err(db_err)?;
                    conn.execute_batch(&format!("PRAGMA user_version = {version}"))
                        .map_err(db_err)?;
                } else {
                    // Use an explicit transaction so the schema DDL and the
                    // PRAGMA user_version bump are atomic.  unchecked_transaction
                    // is safe here because Store is single-writer by design: each
                    // kithd instance opens exactly one Connection per mailbox file
                    // and no other writer ever holds the database open concurrently.
                    let tx = conn.unchecked_transaction().map_err(db_err)?;
                    tx.execute_batch(sql).map_err(db_err)?;
                    // PRAGMA does not accept bound parameters; version is a
                    // compile-time constant u32, so format! interpolation is safe.
                    tx.execute_batch(&format!("PRAGMA user_version = {version}"))
                        .map_err(db_err)?;
                    tx.commit().map_err(db_err)?;
                }
            }
        }
        Ok(())
    }

    /// Return a ChatStore view over this connection.
    pub fn chats(&self) -> chat::ChatStore<'_> {
        chat::ChatStore::new(&self.conn, self.events_tx.as_ref())
    }

    /// Return a ContactStore view over this connection.
    pub fn contacts(&self) -> contact::ContactStore<'_> {
        contact::ContactStore::new(&self.conn, self.events_tx.as_ref())
    }

    /// Return an AttachmentStore view over this connection.
    pub fn attachments(&self) -> attachment::AttachmentStore<'_> {
        attachment::AttachmentStore::new(&self.conn)
    }

    /// Return a MessageStore view over this connection.
    pub fn messages(&self) -> message::MessageStore<'_> {
        message::MessageStore::new(&self.conn, self.events_tx.as_ref())
    }

    /// Return an OutboxStore view over this connection.
    pub fn outbox(&self) -> outbox::OutboxStore<'_> {
        outbox::OutboxStore::new(&self.conn, self.events_tx.as_ref())
    }

    /// Look up the peer mailbox host and attachment metadata for a given blob_id.
    ///
    /// Joins `attachments → messages → contacts` to resolve which peer's mailbox
    /// holds the blob.  Returns `Ok(None)` when:
    /// - `blob_id` does not exist in the `attachments` table, or
    /// - the message's `sender_user_id` has no row in `contacts` (i.e. the
    ///   attachment belongs to an owner-sent message, not a peer-delivered one).
    ///
    /// Returns `Err(KithError::Store(...))` only on a database I/O failure.
    pub fn get_peer_mailbox_for_blob(
        &self,
        blob_id: &str,
    ) -> Result<Option<PeerBlobInfo>, KithError> {
        self.conn
            .query_row(
                "SELECT c.peer_mailbox_host, a.filename, a.content_type, a.sha256, a.size_bytes \
                 FROM attachments a \
                 JOIN messages m ON a.message_id = m.id \
                 JOIN contacts c ON m.sender_user_id = c.peer_user_id \
                 WHERE a.id = ?1 \
                 LIMIT 1",
                rusqlite::params![blob_id],
                |row| {
                    let size_bytes_i64: i64 = row.get(4)?;
                    // size_bytes is always non-negative at write time; a negative
                    // value means DB corruption — reject rather than silently clamp.
                    if size_bytes_i64 < 0 {
                        return Err(rusqlite::Error::IntegralValueOutOfRange(4, size_bytes_i64));
                    }
                    Ok(PeerBlobInfo {
                        mailbox_host: row.get(0)?,
                        filename: row.get(1)?,
                        content_type: row.get(2)?,
                        sha256: row.get(3)?,
                        size_bytes: size_bytes_i64 as u64,
                    })
                },
            )
            .optional()
            .map_err(db_err)
    }

    /// Return `true` if this mailbox has never had a contact added.
    ///
    /// Used at startup to detect a freshly-initialized mailbox and log a
    /// welcome message.  A mailbox is considered "first run" when the
    /// `contacts` table is empty.
    pub fn is_first_run(&self) -> Result<bool, KithError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM contacts", [], |row| row.get(0))
            .map_err(db_err)?;
        Ok(count == 0)
    }

    /// Insert a message and all its attachment rows in a single transaction.
    ///
    /// If any step fails — including a UNIQUE constraint violation on an
    /// attachment `id` — the transaction is rolled back automatically (on
    /// `Transaction` drop), leaving the database unchanged.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_message_with_attachments(
        &self,
        id: &str,
        chat_id: &str,
        sender_user_id: &str,
        body: &str,
        body_type: &str,
        sent_at_peer: Option<&str>,
        created_at_unix: i64,
        delivery_state: &DeliveryState,
        reply_to: Option<&str>,
        sender_msg_id: &str,
        attachments: &[Attachment],
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let version = advance_state_counter_in_tx(&tx, "message")?;
        let state_str = match delivery_state {
            DeliveryState::Pending => "pending",
            DeliveryState::Delivered => "delivered",
            DeliveryState::Failed => "failed",
            DeliveryState::Received => "received",
        };
        tx.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, body_type, sent_at_peer, \
              created_at, state_version, created_at_version, delivery_state, reply_to, sender_msg_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                id,
                chat_id,
                sender_user_id,
                body,
                body_type,
                sent_at_peer,
                created_at_unix,
                version,
                state_str,
                reply_to,
                sender_msg_id
            ],
        )
        .map_err(db_err)?;
        for att in attachments {
            let size_i64 = i64::try_from(att.size)
                .map_err(|_| KithError::Store("attachment size exceeds i64::MAX".into()))?;
            tx.execute(
                "INSERT INTO attachments \
                     (id, message_id, filename, content_type, size_bytes, sha256, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    att.blob_id,
                    id,
                    att.filename,
                    att.content_type,
                    size_i64,
                    att.sha256,
                    created_at_unix
                ],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        if let Some(ref tx_ch) = self.events_tx {
            let _ = tx_ch.send(StateChange {
                type_name: "Message".to_string(),
                new_state: format!("s-{version}"),
            });
        }
        Ok(())
    }

    /// Insert an outbound (owner-sent) message with its attachments and outbox
    /// entries in a single atomic transaction.
    ///
    /// The message, all attachment rows, and all outbox rows are written inside
    /// one `BEGIN … COMMIT` block.  If any insert fails the entire transaction
    /// is rolled back — no Pending message with missing outbox entries will be
    /// left in the database.
    ///
    /// For outbound messages `sender_user_id` is always `"self"` and
    /// `sender_msg_id` is always equal to `id` — both are baked in here rather
    /// than threaded through as parameters.
    pub fn insert_outbound_message(
        &self,
        params: &OutboundMessageParams<'_>,
    ) -> Result<(), KithError> {
        let OutboundMessageParams {
            id,
            chat_id,
            body,
            body_type,
            sent_at_peer,
            created_at_unix,
            reply_to,
            attachments,
            outbox_peers,
        } = params;
        // Callers must resolve and validate all outbox peers before calling
        // this function.  An empty slice would commit a Pending message with
        // no outbox entry — the retry loop would never fire and the caller
        // would never learn of the failure.
        if outbox_peers.is_empty() {
            return Err(KithError::Validation(
                "outbox_peers must not be empty".to_string(),
            ));
        }
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;
        let version = advance_state_counter_in_tx(&tx, "message")?;
        // ?1 = id (reused as sender_msg_id at position 11 — outbound msgs
        // always have sender_msg_id == id).
        tx.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, body_type, sent_at_peer, \
              created_at, state_version, created_at_version, delivery_state, reply_to, sender_msg_id) \
             VALUES (?1, ?2, 'self', ?3, ?4, ?5, ?6, ?7, ?7, 'pending', ?8, ?1)",
            rusqlite::params![
                id,
                chat_id,
                body,
                body_type,
                sent_at_peer,
                created_at_unix,
                version,
                reply_to,
            ],
        )
        .map_err(db_err)?;
        for att in *attachments {
            let size_i64 = i64::try_from(att.size)
                .map_err(|_| KithError::Store("attachment size exceeds i64::MAX".into()))?;
            tx.execute(
                "INSERT INTO attachments \
                     (id, message_id, filename, content_type, size_bytes, sha256, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    att.blob_id,
                    id,
                    att.filename,
                    att.content_type,
                    size_i64,
                    att.sha256,
                    created_at_unix
                ],
            )
            .map_err(db_err)?;
        }
        for (peer_user_id, peer_mailbox_host) in *outbox_peers {
            tx.execute(
                "INSERT INTO outbox \
                 (message_id, peer_user_id, peer_mailbox_host, next_attempt_at, attempt_count) \
                 VALUES (?1, ?2, ?3, 0, 0)",
                rusqlite::params![id, peer_user_id, peer_mailbox_host],
            )
            .map_err(db_err)?;
        }
        tx.commit().map_err(db_err)?;
        if let Some(ref tx_ch) = self.events_tx {
            let _ = tx_ch.send(StateChange {
                type_name: "Message".to_string(),
                new_state: format!("s-{version}"),
            });
        }
        Ok(())
    }

    /// Fetch all three JMAP state counters in a single SQL query.
    ///
    /// Returns `[("ChatContact", "s-N"), ("Chat", "s-N"), ("Message", "s-N")]`.
    /// Any type whose row is missing from `state_counters` defaults to `"s-0"`.
    pub fn get_all_states(&self) -> Result<[(&'static str, String); 3], kith_core::KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT type_name, counter FROM state_counters \
                 WHERE type_name IN ('contact', 'chat', 'message')",
            )
            .map_err(db_err)?;

        let mut contact: Option<String> = None;
        let mut chat: Option<String> = None;
        let mut message: Option<String> = None;

        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let counter: i64 = row.get(1)?;
                Ok((name, counter))
            })
            .map_err(db_err)?;

        for row in rows {
            let (name, counter) = row.map_err(db_err)?;
            let state = format!("s-{counter}");
            match name.as_str() {
                "contact" => contact = Some(state),
                "chat" => chat = Some(state),
                "message" => message = Some(state),
                _ => {}
            }
        }

        // All three rows must be present — a missing row indicates DB corruption
        // or a failed migration (not a legitimate "counter=0" state, because
        // migrations always insert all three rows).
        let contact = contact
            .ok_or_else(|| KithError::Store("state_counters missing 'contact' row".into()))?;
        let chat =
            chat.ok_or_else(|| KithError::Store("state_counters missing 'chat' row".into()))?;
        let message = message
            .ok_or_else(|| KithError::Store("state_counters missing 'message' row".into()))?;

        Ok([
            ("ChatContact", contact),
            ("Chat", chat),
            ("Message", message),
        ])
    }
}

/// Convert a rusqlite error into the crate-level KithError.
///
/// A blanket `impl From<rusqlite::Error> for KithError` would violate the
/// orphan rule (both types are external to this crate).  Call sites within
/// kith-store use `.map_err(db_err)` at every rusqlite boundary.
///
/// Error classification:
/// - **Constraint violation** (`SQLITE_CONSTRAINT`) → `KithError::Validation`.
///   These arise from invalid client input (duplicate IDs, FK violations, CHECK
///   constraint failures).  Callers that surface `KithError` to JMAP will
///   automatically map `Validation` → `invalidArguments`, which is correct.
/// - **All other errors** → `KithError::Store`.  These represent genuine storage
///   failures (I/O, corruption, type mismatch) and map to `serverFail`.
fn db_err(e: rusqlite::Error) -> KithError {
    if let rusqlite::Error::SqliteFailure(ref ffi_err, _) = e {
        if ffi_err.code == rusqlite::ErrorCode::ConstraintViolation {
            return KithError::Validation(format!("constraint violation: {e}"));
        }
    }
    KithError::Store(e.to_string())
}

/// Increment the named state counter inside an already-open transaction and
/// return the new value.
///
/// The caller owns the transaction and is responsible for committing or
/// rolling it back.  This function only issues two SQL statements against
/// the provided `tx` handle; it never opens or closes a transaction.
///
/// # Concurrency
/// The UPDATE followed by SELECT reads the counter in two separate
/// statements.  This is safe only for single-threaded use (Phase 1
/// constraint).  Phase 2, if it introduces concurrent writers, must replace
/// these two statements with a single `UPDATE … RETURNING`.
pub(crate) fn advance_state_counter_in_tx(
    tx: &rusqlite::Transaction<'_>,
    type_name: &str,
) -> Result<i64, KithError> {
    let current: i64 = tx
        .query_row(
            "SELECT counter FROM state_counters WHERE type_name = ?1",
            rusqlite::params![type_name],
            |row| row.get(0),
        )
        .map_err(|e| {
            if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                KithError::Store(format!(
                    "advance_state_counter: unknown type_name '{type_name}'"
                ))
            } else {
                db_err(e)
            }
        })?;
    // Guard against i64 overflow on the state counter. At 2^63-1 increments
    // a personal mailbox has sent more messages than atoms in the universe —
    // this is defence-in-depth, not a practical concern.
    if current >= i64::MAX - 1 {
        return Err(KithError::Store("state counter overflow".to_string()));
    }
    let rows = tx
        .execute(
            "UPDATE state_counters SET counter = counter + 1 WHERE type_name = ?1",
            rusqlite::params![type_name],
        )
        .map_err(db_err)?;
    if rows != 1 {
        return Err(KithError::Store(format!(
            "advance_state_counter: unknown type_name '{type_name}'"
        )));
    }
    Ok(current + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_succeeds() {
        Store::open_in_memory().expect("in-memory store should open without error");
    }

    #[test]
    fn wal_mode_enabled() {
        let store = Store::open_in_memory().unwrap();
        // In-memory databases always return "memory" for journal_mode, but the
        // PRAGMA must at least execute without error — that is what we verified
        // above.  For a real file we would assert "wal".
        let _: String = store
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
    }

    #[test]
    fn foreign_keys_enabled() {
        let store = Store::open_in_memory().unwrap();
        let fk: i64 = store
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys PRAGMA must be ON (1)");
    }

    #[test]
    fn user_version_after_migration() {
        let store = Store::open_in_memory().unwrap();
        let version: u32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        // MIGRATIONS has nineteen entries (versions 1-19), so user_version must be 19 after open.
        assert_eq!(version, 19);
    }

    #[test]
    fn db_err_produces_store_variant() {
        // Oracle: a SQL error that is not a constraint violation (no_such_table
        // gives SQLITE_ERROR, not SQLITE_CONSTRAINT) must map to KithError::Store.
        let conn = Connection::open_in_memory().unwrap();
        let result: Result<i64, rusqlite::Error> =
            conn.query_row("SELECT 1 FROM no_such_table", [], |row| row.get(0));
        let kith_err = db_err(result.unwrap_err());
        match kith_err {
            KithError::Store(msg) => assert!(!msg.is_empty()),
            other => panic!("expected KithError::Store, got {:?}", other),
        }
    }

    #[test]
    fn db_err_constraint_violation_produces_validation_variant() {
        // Oracle: UNIQUE constraint violations (SQLITE_CONSTRAINT) must map to
        // KithError::Validation so callers can surface them as invalidArguments
        // rather than serverFail.  The oracle is the SQLite error code
        // SQLITE_CONSTRAINT (19), which rusqlite exposes as ErrorCode::ConstraintViolation.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .unwrap();
        conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        // Second INSERT with same PK triggers UNIQUE constraint violation.
        let result: Result<usize, rusqlite::Error> = conn.execute("INSERT INTO t VALUES (1)", []);
        let kith_err = db_err(result.unwrap_err());
        match kith_err {
            KithError::Validation(msg) => {
                assert!(
                    msg.contains("constraint"),
                    "validation message must mention 'constraint', got: {msg}"
                );
            }
            other => panic!(
                "UNIQUE constraint violation must map to KithError::Validation, got {:?}",
                other
            ),
        }
    }

    // --- Specification-driven tests (Agent T) ---
    // Oracle: rusqlite PRAGMA user_version semantics (SQLite docs), WAL mode
    // behavior, and FK enforcement behavior.

    #[test]
    fn migrate_is_idempotent() {
        // Oracle: PRAGMA user_version semantics (SQLite docs §6.19).
        // user_version is advanced to the highest migration version applied.
        // Calling open_in_memory twice (two separate in-memory DBs) must both
        // yield the same user_version, and neither call may fail.
        let store1 = Store::open_in_memory().expect("first open");
        let store2 = Store::open_in_memory().expect("second open");
        let v1: u32 = store1
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let v2: u32 = store2
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v1, 19, "migration 19 must be applied");
        assert_eq!(v1, v2, "migrate must be idempotent across opens");
    }

    #[test]
    fn foreign_keys_enforced() {
        // Oracle: PRAGMA foreign_keys documentation.
        // Default is OFF (0). init_conn must set it ON (1).
        let store = Store::open_in_memory().expect("open");
        let fk: i32 = store
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1, "foreign_keys must be ON");
    }

    #[test]
    fn schema_v1_tables_exist() {
        // Oracle: we define these tables in SCHEMA_V1; after migration they must exist.
        let store = Store::open_in_memory().expect("open");
        let mut stmt = store
            .conn
            .prepare_cached("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        let tables: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        for expected in &[
            "attachments",
            "chat_members",
            "chats",
            "contacts",
            "messages",
            "outbox",
            "self",
            "state_counters",
        ] {
            assert!(
                tables.contains(&expected.to_string()),
                "expected table '{}' to exist after migration, found: {:?}",
                expected,
                tables
            );
        }
    }

    #[test]
    fn schema_v1_indexes_exist() {
        // Oracle: SCHEMA_V1 defines these 3 indexes; verify they exist after migration.
        let store = Store::open_in_memory().expect("open");
        let mut stmt = store
            .conn
            .prepare_cached("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name")
            .unwrap();
        let indexes: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .filter(|n: &String| !n.starts_with("sqlite_"))
            .collect();

        for expected in &[
            "messages_chat_time",
            "messages_pending",
            "messages_unread",
            "outbox_next",
        ] {
            assert!(
                indexes.contains(&expected.to_string()),
                "expected index '{}' to exist, found: {:?}",
                expected,
                indexes
            );
        }
    }

    #[test]
    fn schema_user_version_after_all_migrations() {
        // Oracle: PRAGMA user_version semantics. After applying migration 1, version must be 1.
        let store = Store::open_in_memory().expect("open");
        let v: u32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, 19, "migration v19 must set user_version to 19");
    }

    #[test]
    fn state_counters_initialized() {
        // Oracle: SCHEMA_V1 inserts initial rows for contact, chat, message.
        let store = Store::open_in_memory().expect("open");
        for type_name in &["contact", "chat", "message"] {
            let count: i64 = store
                .conn
                .query_row(
                    "SELECT counter FROM state_counters WHERE type_name = ?1",
                    [type_name],
                    |row| row.get(0),
                )
                .unwrap_or_else(|_| panic!("state_counter for '{}' should exist", type_name));
            assert_eq!(count, 0, "initial counter for '{}' should be 0", type_name);
        }
    }

    #[test]
    fn delivery_state_check_constraint() {
        // Oracle: the CHECK constraint on delivery_state rejects invalid values.
        let store = Store::open_in_memory().expect("open");
        // Insert a chat first (FK required by messages).
        store
            .conn
            .execute(
                "INSERT INTO chats (id, kind, created_at) VALUES (?1, 'direct', ?2)",
                rusqlite::params!["chat-001", 1000i64],
            )
            .unwrap();
        // Insert a message with an invalid delivery_state — must fail.
        let result = store.conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "msg-001",
                "chat-001",
                "user-abc",
                "hello",
                1000i64,
                "invalid_state"
            ],
        );
        assert!(
            result.is_err(),
            "CHECK constraint must reject invalid delivery_state"
        );
    }

    #[test]
    fn foreign_key_violation_rejected() {
        // Oracle: SQLite FK constraint behavior with PRAGMA foreign_keys=ON.
        // Inserting a message that references a non-existent chat_id must fail.
        let store = Store::open_in_memory().expect("open");
        let result = store.conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "msg-fk-test",
                "nonexistent-chat",
                "user-x",
                "body",
                1000i64,
                "pending"
            ],
        );
        assert!(
            result.is_err(),
            "FK constraint must reject message with non-existent chat_id"
        );

        // Also verify attachment FK: attachment referencing a non-existent message.
        let result2 = store.conn.execute(
            "INSERT INTO attachments \
             (id, message_id, filename, content_type, size_bytes, sha256, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "blob-fk-test",
                "nonexistent-message",
                "file.txt",
                "text/plain",
                100i64,
                "aaaa",
                1000i64
            ],
        );
        assert!(
            result2.is_err(),
            "FK constraint must reject attachment with non-existent message_id"
        );
    }

    #[test]
    fn test_message_insert_emits_state_change() {
        // Oracle: RFC 8620 type name for messages is "Message" (capitalized).
        // After MessageStore::insert(), a StateChange must be emitted.
        let (tx, mut rx) = tokio::sync::broadcast::channel(100);
        let mut store = Store::open_in_memory().expect("open");
        store.set_events_tx(tx);

        // FK dep: create a chat row directly.
        store
            .conn
            .execute(
                "INSERT INTO chats (id, kind, created_at) VALUES (?1, 'direct', ?2)",
                rusqlite::params!["chat-001", 1000i64],
            )
            .unwrap();

        store
            .messages()
            .insert(
                "msg-001",
                "chat-001",
                "user-abc",
                "Hello",
                "text/plain",
                None,
                1_000_000,
                &kith_core::DeliveryState::Received,
                None,
                "msg-001",
            )
            .expect("insert");

        let change = rx
            .try_recv()
            .expect("StateChange must be emitted on insert");
        assert_eq!(change.type_name, "Message");
        // Oracle: new_state matches what get_state returns independently.
        let expected = store.messages().get_state().expect("get_state");
        assert_eq!(change.new_state, expected);
    }

    #[test]
    fn test_chat_update_emits_state_change() {
        // Oracle: RFC 8620 type name for chats is "Chat".
        let (tx, mut rx) = tokio::sync::broadcast::channel(100);
        let mut store = Store::open_in_memory().expect("open");
        store.set_events_tx(tx);

        store
            .chats()
            .create("chat-aaa", "direct", Some("uid-bob"), 1_000_000)
            .expect("create");
        // Drain the initial state change from create.
        let _ = rx.try_recv();

        store
            .chats()
            .update_last_message_at("chat-aaa", 2_000_000)
            .expect("update");

        let change = rx
            .try_recv()
            .expect("StateChange must be emitted on update");
        assert_eq!(change.type_name, "Chat");
        let expected = store.chats().get_state().expect("get_state");
        assert_eq!(change.new_state, expected);
    }

    #[test]
    fn test_set_blocked_noop_no_emit() {
        // Oracle: bead spec — only emit when state is actually advanced (rows_affected > 0).
        // set_blocked on nonexistent peer is a no-op; must not emit.
        let (tx, mut rx) = tokio::sync::broadcast::channel(100);
        let mut store = Store::open_in_memory().expect("open");
        store.set_events_tx(tx);

        store
            .contacts()
            .set_blocked("nonexistent-user", true)
            .expect("set_blocked on nonexistent peer");

        assert!(
            rx.try_recv().is_err(),
            "set_blocked on nonexistent peer must not emit StateChange"
        );
    }

    #[test]
    fn is_first_run_true_on_empty_store() {
        // Oracle: a freshly-opened store has zero contacts rows.
        let store = Store::open_in_memory().expect("open");
        assert!(
            store.is_first_run().expect("is_first_run must not fail"),
            "is_first_run must return true when contacts table is empty"
        );
    }

    #[test]
    fn is_first_run_false_after_contact_added() {
        // Oracle: after inserting one contact row, is_first_run must return false.
        let store = Store::open_in_memory().expect("open");
        store
            .contacts()
            .upsert(
                "uid-some-peer",
                "peer@example.com",
                "peer-kith.tail.ts.net",
                None,
                1_000_000,
            )
            .expect("upsert must succeed");
        assert!(
            !store.is_first_run().expect("is_first_run must not fail"),
            "is_first_run must return false after a contact has been added"
        );
    }

    // --- get_peer_mailbox_for_blob tests ---
    // Oracle: SQL JOIN semantics (attachments → messages → contacts).
    // Expected field values are the literals inserted directly into the DB;
    // no code-under-test is used to derive them.

    /// Insert the full prerequisite chain: contact → chat → message → attachment.
    fn insert_peer_blob_fixture(
        conn: &Connection,
        peer_user_id: &str,
        peer_mailbox_host: &str,
        chat_id: &str,
        message_id: &str,
        blob_id: &str,
    ) {
        conn.execute(
            "INSERT INTO contacts \
             (peer_user_id, peer_login, peer_mailbox_host, first_seen_at, last_seen_at, blocked) \
             VALUES (?1, 'peer@example.com', ?2, 1000, 1000, 0)",
            rusqlite::params![peer_user_id, peer_mailbox_host],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO chats (id, kind, created_at) VALUES (?1, 'direct', 1000)",
            rusqlite::params![chat_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
             VALUES (?1, ?2, ?3, 'hello', 1000, 'received', ?1)",
            rusqlite::params![message_id, chat_id, peer_user_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO attachments \
             (id, message_id, filename, content_type, size_bytes, sha256, created_at) \
             VALUES (?1, ?2, 'photo.png', 'image/png', 4096, 'aabbcc', 1000)",
            rusqlite::params![blob_id, message_id],
        )
        .unwrap();
    }

    #[test]
    fn get_peer_mailbox_for_blob_returns_correct_fields() {
        // Oracle: values are identical to the literals inserted above.
        let store = Store::open_in_memory().expect("open");
        insert_peer_blob_fixture(
            &store.conn,
            "uid-peer-1",
            "peer1.tail.ts.net",
            "chat-p1",
            "msg-p1",
            "blob-p1",
        );

        let info = store
            .get_peer_mailbox_for_blob("blob-p1")
            .expect("DB must not error")
            .expect("blob-p1 must be found");

        assert_eq!(info.mailbox_host, "peer1.tail.ts.net");
        assert_eq!(info.filename, "photo.png");
        assert_eq!(info.content_type, "image/png");
        assert_eq!(info.sha256, "aabbcc");
        assert_eq!(info.size_bytes, 4096u64);
    }

    #[test]
    fn get_peer_mailbox_for_blob_owner_message_returns_none() {
        // Oracle: when sender_user_id has no contacts row, the JOIN produces
        // zero rows, and the method must return Ok(None).
        let store = Store::open_in_memory().expect("open");

        // Insert chat + message without a corresponding contacts row.
        store
            .conn
            .execute(
                "INSERT INTO chats (id, kind, created_at) VALUES ('chat-own', 'direct', 1000)",
                [],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO messages \
                 (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
                 VALUES ('msg-own', 'chat-own', 'uid-owner', 'hi', 1000, 'pending', 'msg-own')",
                [],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO attachments \
                 (id, message_id, filename, content_type, size_bytes, sha256, created_at) \
                 VALUES ('blob-own', 'msg-own', 'doc.pdf', 'application/pdf', 512, 'ddee', 1000)",
                [],
            )
            .unwrap();

        let result = store
            .get_peer_mailbox_for_blob("blob-own")
            .expect("DB must not error");
        assert!(
            result.is_none(),
            "blob for owner-sent message must return None (no contacts row)"
        );
    }

    #[test]
    fn get_peer_mailbox_for_blob_unknown_blob_id_returns_none() {
        // Oracle: no rows in attachments for an unknown blob_id; JOIN produces nothing.
        let store = Store::open_in_memory().expect("open");
        let result = store
            .get_peer_mailbox_for_blob("no-such-blob")
            .expect("DB must not error");
        assert!(result.is_none(), "unknown blob_id must return None");
    }

    #[test]
    fn test_contact_upsert_emits_state_change() {
        // Oracle: RFC 8620 type name for contacts is "ChatContact".
        let (tx, mut rx) = tokio::sync::broadcast::channel(100);
        let mut store = Store::open_in_memory().expect("open");
        store.set_events_tx(tx);

        store
            .contacts()
            .upsert(
                "uid-1",
                "alice@example.com",
                "alice.tail.ts.net",
                Some("Alice"),
                1000,
            )
            .expect("upsert");

        let change = rx
            .try_recv()
            .expect("StateChange must be emitted on upsert");
        assert_eq!(change.type_name, "ChatContact");
        let expected = store.contacts().get_state().expect("get_state");
        assert_eq!(change.new_state, expected);
    }

    // Oracle: if a V4 database has duplicate (chat_id, sender_msg_id) rows
    // (possible when KITH-orvy.1 was present and a retransmission occurred),
    // the V5 migration must succeed by deduplicating first rather than failing
    // with a UNIQUE constraint error.
    //
    // Independent oracle: after migration, SELECT COUNT(*) for the duplicate
    // pair returns 1 (not 2), and the UNIQUE index exists.
    #[test]
    fn v5_migration_deduplicates_before_creating_unique_index() {
        use rusqlite::Connection;

        // Build a V4 database by applying migrations 1-4 on a raw connection.
        let conn = Connection::open_in_memory().unwrap();
        Store::init_conn(&conn).unwrap();
        for &(version, sql) in MIGRATIONS {
            if version <= 4 {
                conn.execute_batch(sql).unwrap();
                conn.execute_batch(&format!("PRAGMA user_version = {version}"))
                    .unwrap();
            }
        }

        // Insert the prerequisite chat row (FK required by messages).
        conn.execute(
            "INSERT INTO chats (id, kind, created_at) VALUES ('chat-dup', 'direct', 1000)",
            [],
        )
        .unwrap();

        // Insert two messages with the same (chat_id, sender_msg_id) — simulating
        // the retransmission-duplicate bug that KITH-orvy.3 fixed.
        // At V4 the index is non-unique so this succeeds.
        let dup_sender_msg_id = "sender-ulid-duplicate";
        conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
             VALUES ('msg-a', 'chat-dup', 'uid-peer', 'first',  1001, 'received', ?1)",
            rusqlite::params![dup_sender_msg_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
             VALUES ('msg-b', 'chat-dup', 'uid-peer', 'second', 1002, 'received', ?1)",
            rusqlite::params![dup_sender_msg_id],
        )
        .unwrap();

        // Pre-flight: confirm two rows exist before V5.
        let count_before: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE sender_msg_id = ?1",
                rusqlite::params![dup_sender_msg_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count_before, 2, "two duplicate rows must exist before V5");

        // Apply V5 — must succeed (no UNIQUE constraint error).
        conn.execute_batch(SCHEMA_V5)
            .expect("V5 migration must succeed even with pre-existing duplicate rows");

        // Oracle: exactly one row remains for the duplicate sender_msg_id.
        let count_after: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE sender_msg_id = ?1",
                rusqlite::params![dup_sender_msg_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count_after, 1,
            "dedup must leave exactly one row per (chat_id, sender_msg_id)"
        );

        // Oracle: the retained row is the one with the smaller rowid (first received).
        let retained_id: String = conn
            .query_row(
                "SELECT id FROM messages WHERE sender_msg_id = ?1",
                rusqlite::params![dup_sender_msg_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            retained_id, "msg-a",
            "MIN(rowid) — the first-received message — must be retained"
        );

        // Oracle: the UNIQUE index now exists.
        let idx_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='index' AND name='messages_sender_msg_id'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(idx_exists, 1, "UNIQUE index must exist after V5 migration");
    }

    #[test]
    fn v6_trigger_rejects_null_sender_msg_id() {
        use rusqlite::Connection;

        // Apply all migrations up through V6 on a fresh in-memory database.
        let conn = Connection::open_in_memory().unwrap();
        Store::init_conn(&conn).unwrap();
        for &(version, sql) in MIGRATIONS {
            conn.execute_batch(sql).unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {version}"))
                .unwrap();
        }

        // Prerequisite: a chat row for the FK.
        conn.execute(
            "INSERT INTO chats (id, kind, created_at) VALUES ('chat-trigger', 'direct', 1000)",
            [],
        )
        .unwrap();

        // Oracle: inserting with a non-NULL sender_msg_id must succeed.
        conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
             VALUES ('msg-ok', 'chat-trigger', 'uid-peer', 'hello', 1001, 'received', 'sender-ulid-1')",
            [],
        )
        .expect("non-NULL sender_msg_id must be accepted");

        // Oracle: inserting with a NULL sender_msg_id must be rejected by the trigger.
        let result = conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
             VALUES ('msg-bad', 'chat-trigger', 'uid-peer', 'oops', 1002, 'received', NULL)",
            [],
        );
        assert!(result.is_err(), "V6 trigger must reject NULL sender_msg_id");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("sender_msg_id must not be NULL"),
            "error must identify the invariant; got: {err_msg}"
        );
    }

    #[test]
    fn advance_state_counter_overflow_guard() {
        // Oracle: the guard must fire at i64::MAX - 1, before any increment
        // would wrap to a negative value or silently overflow.
        // We set the counter to i64::MAX - 1 directly in SQL, then verify that
        // advance_state_counter_in_tx returns Err rather than incrementing.
        let store = Store::open_in_memory().expect("open");
        store
            .conn
            .execute(
                "UPDATE state_counters SET counter = ?1 WHERE type_name = 'message'",
                rusqlite::params![i64::MAX - 1],
            )
            .expect("set counter to MAX-1");

        let tx = store
            .conn
            .unchecked_transaction()
            .expect("open transaction");
        let result = advance_state_counter_in_tx(&tx, "message");
        assert!(
            result.is_err(),
            "advance_state_counter_in_tx must return Err when counter is at i64::MAX-1"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("state counter overflow"),
            "error must mention overflow; got: {err_msg}"
        );
        // Counter must not have been modified.
        let _ = tx.rollback();
        let counter_after: i64 = store
            .conn
            .query_row(
                "SELECT counter FROM state_counters WHERE type_name = 'message'",
                [],
                |row| row.get(0),
            )
            .expect("read counter");
        assert_eq!(
            counter_after,
            i64::MAX - 1,
            "counter must be unchanged after overflow guard fires"
        );
    }

    #[test]
    fn advance_state_counter_overflow_guard_at_max() {
        // Oracle: a counter already at i64::MAX must also be rejected.
        let store = Store::open_in_memory().expect("open");
        store
            .conn
            .execute(
                "UPDATE state_counters SET counter = ?1 WHERE type_name = 'message'",
                rusqlite::params![i64::MAX],
            )
            .expect("set counter to MAX");

        let tx = store
            .conn
            .unchecked_transaction()
            .expect("open transaction");
        let result = advance_state_counter_in_tx(&tx, "message");
        assert!(
            result.is_err(),
            "advance_state_counter_in_tx must return Err when counter is at i64::MAX"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("state counter overflow"),
            "error must mention overflow; got: {err_msg}"
        );
    }

    #[test]
    fn v14_trigger_rejects_second_self_row() {
        // Oracle: the V14 self_singleton trigger must reject any INSERT that
        // would produce a second row in the self table.
        let store = Store::open_in_memory().expect("open");

        // Insert the first (and only) allowed row.
        store
            .conn
            .execute(
                "INSERT INTO self (tailscale_user_id, tailscale_login, created_at) \
                 VALUES ('uid-alice', 'alice@example.com', 1000)",
                [],
            )
            .expect("first INSERT into self must succeed");

        // A second INSERT must be rejected by the trigger.
        let result = store.conn.execute(
            "INSERT INTO self (tailscale_user_id, tailscale_login, created_at) \
             VALUES ('uid-bob', 'bob@example.com', 2000)",
            [],
        );
        assert!(
            result.is_err(),
            "self_singleton trigger must reject a second INSERT into self"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("self table must contain exactly one row"),
            "error must identify the violated invariant; got: {err_msg}"
        );

        // Oracle: exactly one row remains.
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM self", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            count, 1,
            "self table must contain exactly one row after rejected INSERT"
        );
    }

    #[test]
    fn insert_outbound_message_empty_peers_returns_err() {
        // Oracle: an empty outbox_peers slice would commit a Pending message with
        // no outbox row, making it permanently stuck.  The guard must reject this
        // before touching the database and must NOT advance the message state counter.
        let store = Store::open_in_memory().expect("open");
        store
            .conn
            .execute(
                "INSERT INTO chats (id, kind, created_at) VALUES ('chat-ep', 'direct', 1000)",
                [],
            )
            .unwrap();

        let ms = store.messages();
        let state_before = ms.get_state().expect("state before");

        let result = store.insert_outbound_message(&OutboundMessageParams {
            id: "msg-ep",
            chat_id: "chat-ep",
            body: "hello",
            body_type: "text/plain",
            sent_at_peer: None,
            created_at_unix: 1000,
            reply_to: None,
            attachments: &[],
            outbox_peers: &[],
        });
        assert!(
            result.is_err(),
            "insert_outbound_message with empty outbox_peers must return Err"
        );

        // No message row must have been inserted.
        let msg = ms.get("msg-ep").expect("get must not error");
        assert!(
            msg.is_none(),
            "no message row must exist after rejected insert"
        );

        // State counter must not have advanced.
        let state_after = ms.get_state().expect("state after");
        assert_eq!(
            state_before, state_after,
            "state counter must not advance when insert_outbound_message rejects empty peers"
        );
    }
}
