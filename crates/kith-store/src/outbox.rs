use crate::db_err;
use kith_core::{KithError, StateChange};
use rand::Rng;
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::broadcast;

/// Maximum number of delivery attempts before an outbox entry is marked failed.
const MAX_DELIVERY_ATTEMPTS: i64 = 72;

#[derive(Debug)]
pub struct OutboxEntry {
    pub message_id: String,
    pub peer_user_id: String,
    pub peer_mailbox_host: String,
    pub kind: String,              // "message" or "receipt"
    pub read_at_unix: Option<i64>, // Some(_) for kind="receipt"
    pub next_attempt_at: i64,
    pub attempt_count: u32,
    pub last_error: Option<String>,
}

pub struct OutboxStore<'a> {
    conn: &'a Connection,
    events_tx: Option<&'a broadcast::Sender<StateChange>>,
}

impl<'a> OutboxStore<'a> {
    pub fn new(
        conn: &'a Connection,
        events_tx: Option<&'a broadcast::Sender<StateChange>>,
    ) -> Self {
        OutboxStore { conn, events_tx }
    }

    fn emit(&self, new_state: String) {
        if let Some(tx) = self.events_tx {
            let _ = tx.send(StateChange {
                type_name: "Message".to_string(),
                new_state,
            });
        }
    }

    /// Enqueue a message for delivery. next_attempt_at = now_unix (immediate first attempt).
    ///
    /// Idempotent: if an outbox row already exists for (message_id, peer_user_id, 'message'),
    /// the second call is a no-op (INSERT OR IGNORE).  This prevents a UNIQUE constraint
    /// error when the caller retries after a partial failure.
    pub fn enqueue(
        &self,
        message_id: &str,
        peer_user_id: &str,
        peer_mailbox_host: &str,
        now_unix: i64,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO outbox \
                 (message_id, peer_user_id, peer_mailbox_host, next_attempt_at, attempt_count) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                params![message_id, peer_user_id, peer_mailbox_host, now_unix],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Enqueue a read receipt for delivery. kind='receipt', read_at_unix is required.
    ///
    /// Idempotent: if a receipt is already queued for this (message_id, peer_user_id),
    /// the existing row is updated with the new read_at_unix timestamp and the retry
    /// state is reset. This handles the case where the owner updates readAt multiple
    /// times — the latest timestamp is always used.
    pub fn enqueue_receipt(
        &self,
        message_id: &str,
        peer_user_id: &str,
        peer_mailbox_host: &str,
        read_at_unix: i64,
        now_unix: i64,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "INSERT INTO outbox \
                 (message_id, peer_user_id, peer_mailbox_host, kind, read_at_unix, next_attempt_at, attempt_count) \
                 VALUES (?1, ?2, ?3, 'receipt', ?4, ?5, 0) \
                 ON CONFLICT (message_id, peer_user_id, kind) DO UPDATE SET \
                     read_at_unix      = excluded.read_at_unix, \
                     next_attempt_at   = excluded.next_attempt_at, \
                     attempt_count     = 0, \
                     last_error        = NULL",
                params![message_id, peer_user_id, peer_mailbox_host, read_at_unix, now_unix],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Get all outbox entries due for retry (next_attempt_at <= now), limit 50.
    pub fn get_due(&self, now_unix: i64) -> Result<Vec<OutboxEntry>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT message_id, peer_user_id, peer_mailbox_host, kind, read_at_unix, \
                        next_attempt_at, attempt_count, last_error \
                 FROM outbox \
                 WHERE next_attempt_at <= ?1 \
                 ORDER BY next_attempt_at \
                 LIMIT 50", // LIMIT 50: caps one delivery batch to prevent blocking the retry loop
                            // on a large backlog. With 30s base retry interval, 50 concurrent
                            // delivery attempts per tick is sufficient for typical single-user load.
            )
            .map_err(db_err)?;

        let entries = stmt
            .query_map([now_unix], |row| {
                let attempt_count_raw: i64 = row.get(6)?;
                Ok(OutboxEntry {
                    message_id: row.get(0)?,
                    peer_user_id: row.get(1)?,
                    peer_mailbox_host: row.get(2)?,
                    kind: row.get(3)?,
                    read_at_unix: row.get(4)?,
                    next_attempt_at: row.get(5)?,
                    attempt_count: attempt_count_raw as u32,
                    last_error: row.get(7)?,
                })
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(entries)
    }

    /// Record a delivery failure. Increments attempt_count and schedules next retry
    /// with exponential backoff (30s base, 2× per attempt, 1h cap) and ±20% jitter.
    ///
    /// `attempt_count` is 0-indexed: after `MAX_DELIVERY_ATTEMPTS` calls
    /// (attempt_count reaching `MAX_DELIVERY_ATTEMPTS - 1` before this call),
    /// `mark_failed` is triggered on the final failure.
    ///
    /// # Concurrency
    /// `record_failure` reads then updates `attempt_count` in two separate statements.
    /// Safe only for single-threaded use (Phase 1 constraint). See `advance_state`
    /// comments for the multi-writer upgrade path.
    pub fn record_failure(
        &self,
        entry: &OutboxEntry,
        last_error: &str,
        now_unix: i64,
    ) -> Result<(), KithError> {
        let attempt: i64 = entry.attempt_count as i64;

        // attempt is 0-indexed: completing this call would be attempt+1 total.
        // Once that equals MAX_DELIVERY_ATTEMPTS, the budget is exhausted.
        if attempt + 1 >= MAX_DELIVERY_ATTEMPTS {
            return self.mark_failed(entry, last_error);
        }

        // Clamp the shift to 30 to prevent overflow: 30 * 2^30 would be
        // capped by min(_, 3600) anyway, but the shift itself must not overflow.
        let shift = attempt.min(30);
        let base_delay: i64 = std::cmp::min(30 * (1i64 << shift), 3600);

        // ±20% jitter: randomise within [base - base/5, base + base/5].
        // Clamped to at least 1 second to avoid scheduling in the past.
        let jitter_range = base_delay / 5;
        let jitter: i64 = rand::thread_rng().gen_range(-jitter_range..=jitter_range);
        let delay_secs: i64 = (base_delay + jitter).max(1);

        let next = now_unix + delay_secs;

        // Truncate at a UTF-8 character boundary ≤ 500 bytes to avoid a panic on
        // multi-byte sequences.  last_error comes from internal formatting but may
        // contain non-ASCII from peer hostnames or TLS details.
        let error_truncated = if last_error.len() <= 500 {
            last_error
        } else {
            let boundary = last_error
                .char_indices()
                .take_while(|(i, _)| *i < 500)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(0);
            &last_error[..boundary]
        };

        self.conn
            .execute(
                "UPDATE outbox \
                 SET attempt_count = attempt_count + 1, last_error = ?1, next_attempt_at = ?2 \
                 WHERE message_id = ?3 AND peer_user_id = ?4 AND kind = ?5",
                params![
                    error_truncated,
                    next,
                    entry.message_id,
                    entry.peer_user_id,
                    entry.kind
                ],
            )
            .map_err(db_err)?;

        Ok(())
    }

    /// Mark as successfully delivered: delete the outbox row.
    ///
    /// NOTE: This does not update `messages.delivery_state`. Use `complete_delivery`
    /// for successful delivery; use this only for orphaned outbox rows where the
    /// message no longer exists.
    pub fn mark_delivered(&self, entry: &OutboxEntry) -> Result<(), KithError> {
        self.conn
            .execute(
                "DELETE FROM outbox \
                 WHERE message_id = ?1 AND peer_user_id = ?2 AND kind = ?3",
                params![entry.message_id, entry.peer_user_id, entry.kind],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Atomically mark as successfully delivered: advance the message state counter,
    /// update messages.delivery_state to 'delivered', and delete the outbox row.
    ///
    /// For kind='receipt': only deletes the outbox row (no message state update).
    ///
    /// Mirrors `mark_failed`: all three writes are wrapped in a single transaction so
    /// that a crash between steps cannot leave the message stuck in Pending with no retry
    /// path (the outbox row would be gone but delivery_state still Pending).
    pub fn complete_delivery(
        &self,
        entry: &OutboxEntry,
        delivered_at_unix: i64,
    ) -> Result<(), KithError> {
        if entry.kind == "receipt" {
            return self.delete_outbox_row(entry);
        }
        // kind == "message": transactional delivery with state counter advance.
        self.finish_message_delivery(entry, "delivered", Some(delivered_at_unix))
    }

    /// Permanent failure: update messages.delivery_state to 'failed' (with state counter
    /// advance so Message/changes picks it up), then delete the outbox row.
    ///
    /// For kind='receipt': only deletes the outbox row (no message state update).
    ///
    /// All three writes are wrapped in a single transaction. `unchecked_transaction()` is
    /// safe here because kithd is single-user single-writer — no concurrent writers on
    /// this connection.
    pub fn mark_failed(&self, entry: &OutboxEntry, _last_error: &str) -> Result<(), KithError> {
        if entry.kind == "receipt" {
            return self.delete_outbox_row(entry);
        }
        // kind == "message": transactional failure with state counter advance.
        self.finish_message_delivery(entry, "failed", None)
    }

    /// Delete the outbox row identified by the composite key (message_id, peer_user_id, kind).
    fn delete_outbox_row(&self, entry: &OutboxEntry) -> Result<(), KithError> {
        self.conn
            .execute(
                "DELETE FROM outbox \
                 WHERE message_id = ?1 AND peer_user_id = ?2 AND kind = ?3",
                params![entry.message_id, entry.peer_user_id, entry.kind],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Atomically update messages.delivery_state, advance the message state counter,
    /// delete the outbox row, and emit the new state.
    ///
    /// The state counter is advanced ONLY if the UPDATE touches a row (rows > 0).
    /// If the message row does not exist the counter is not advanced and the outbox
    /// row is still deleted (orphaned outbox entry).
    ///
    /// `delivered_at` is `Some(unix_ts)` for the delivered path, `None` for the
    /// failed path (no `delivered_at` column to set).
    fn finish_message_delivery(
        &self,
        entry: &OutboxEntry,
        final_state: &str,
        delivered_at: Option<i64>,
    ) -> Result<(), KithError> {
        let tx = self.conn.unchecked_transaction().map_err(db_err)?;

        // Ordering requirement: advance the counter FIRST, then stamp state_version
        // on the messages row with that captured value.  This guarantees that
        // state_version on the row equals exactly the counter announced in the
        // StateChange event — never counter+1 from a stale subquery read.
        //
        // If we stamped state_version via a subquery (counter+1) and then advanced
        // the counter, the two values would agree only because SQLite serialises
        // writes within a transaction.  Making the order explicit removes the
        // dependency on that coincidence and makes the invariant self-documenting.
        //
        // The counter is advanced only when the UPDATE actually touches a row.
        // For orphaned outbox entries (message row absent) the counter must not move.

        // First: probe whether the messages row exists and is not already delivered.
        // We use a SELECT rather than a speculative UPDATE so we can branch before
        // touching the counter.
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM messages WHERE id = ?1 AND delivery_state != 'delivered'",
                params![entry.message_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(db_err)?
            .is_some();

        let version = if exists {
            // Advance the counter first; capture the new value.
            let v = crate::advance_state_counter_in_tx(&tx, "message")?;

            // Now stamp the row with the exact counter value we just reserved.
            if let Some(at) = delivered_at {
                tx.execute(
                    "UPDATE messages \
                     SET delivery_state = ?1, delivered_at = ?2, state_version = ?3 \
                     WHERE id = ?4 AND delivery_state != 'delivered'",
                    params![final_state, at, v, entry.message_id],
                )
                .map_err(db_err)?;
            } else {
                tx.execute(
                    "UPDATE messages \
                     SET delivery_state = ?1, state_version = ?2 \
                     WHERE id = ?3 AND delivery_state != 'delivered'",
                    params![final_state, v, entry.message_id],
                )
                .map_err(db_err)?;
            }
            Some(v)
        } else {
            None
        };

        tx.execute(
            "DELETE FROM outbox \
             WHERE message_id = ?1 AND peer_user_id = ?2 AND kind = ?3",
            params![entry.message_id, entry.peer_user_id, entry.kind],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        if let Some(v) = version {
            self.emit(format!("s-{v}"));
        }
        Ok(())
    }

    /// Look up all outbox entries for a given message ID.
    pub fn get_by_message(&self, message_id: &str) -> Result<Vec<OutboxEntry>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT message_id, peer_user_id, peer_mailbox_host, kind, read_at_unix, \
                        next_attempt_at, attempt_count, last_error \
                 FROM outbox \
                 WHERE message_id = ?1",
            )
            .map_err(db_err)?;

        let entries = stmt
            .query_map([message_id], |row| {
                let attempt_count_raw: i64 = row.get(6)?;
                Ok(OutboxEntry {
                    message_id: row.get(0)?,
                    peer_user_id: row.get(1)?,
                    peer_mailbox_host: row.get(2)?,
                    kind: row.get(3)?,
                    read_at_unix: row.get(4)?,
                    next_attempt_at: row.get(5)?,
                    attempt_count: attempt_count_raw as u32,
                    last_error: row.get(7)?,
                })
            })
            .map_err(db_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(db_err)?;

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    fn insert_test_message(conn: &Connection, msg_id: &str) {
        conn.execute(
            "INSERT OR IGNORE INTO chats (id, kind, created_at) VALUES ('chat-1', 'direct', 1000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
             VALUES (?1, 'chat-1', 'user-a', 'hello', 1000, 'pending', ?1)",
            [msg_id],
        )
        .unwrap();
    }

    // Oracle: SQL semantics — enqueue inserts a row with next_attempt_at = now_unix;
    // get_due returns rows where next_attempt_at <= now_unix.

    #[test]
    fn enqueue_then_get_due_at_now_returns_entry() {
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-1");

        let ob = store.outbox();
        ob.enqueue("msg-1", "user-b", "host-b.example.ts.net", 1000)
            .unwrap();

        let due = ob.get_due(1000).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].message_id, "msg-1");
        assert_eq!(due[0].peer_user_id, "user-b");
        assert_eq!(due[0].peer_mailbox_host, "host-b.example.ts.net");
        assert_eq!(due[0].kind, "message");
        assert!(due[0].read_at_unix.is_none());
        assert_eq!(due[0].next_attempt_at, 1000);
        assert_eq!(due[0].attempt_count, 0);
        assert!(due[0].last_error.is_none());
    }

    #[test]
    fn get_due_before_next_attempt_returns_empty() {
        // Oracle: get_due uses WHERE next_attempt_at <= now_unix.
        // If now_unix < next_attempt_at, the row is not yet due.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-2");

        let ob = store.outbox();
        ob.enqueue("msg-2", "user-b", "host-b.example.ts.net", 2000)
            .unwrap();

        // Ask for due entries at t=999, before next_attempt_at=2000.
        let due = ob.get_due(999).unwrap();
        assert!(
            due.is_empty(),
            "no entries should be due before next_attempt_at"
        );
    }

    #[test]
    fn record_failure_increments_attempt_and_schedules_backoff_with_jitter() {
        // Oracle: backoff formula is 30 * 2^attempt_count ± 20% jitter (before increment).
        //   attempt_count=0 → base=30, range=[24, 36]
        //   attempt_count=1 → base=60, range=[48, 72]
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-3");

        let ob = store.outbox();
        let now: i64 = 5000;
        ob.enqueue("msg-3", "user-b", "host-b.example.ts.net", now)
            .unwrap();

        // First failure: attempt_count was 0, base = 30 * 2^0 = 30, ±20% → [24, 36].
        let entries = ob.get_by_message("msg-3").unwrap();
        ob.record_failure(&entries[0], "connection refused", now)
            .unwrap();
        let entries = ob.get_by_message("msg-3").unwrap();
        assert!(!entries.is_empty(), "still in outbox");
        let entry = &entries[0];
        assert_eq!(entry.attempt_count, 1);
        assert!(
            entry.next_attempt_at >= now + 24 && entry.next_attempt_at <= now + 36,
            "first failure: next_attempt_at must be in [now+24, now+36], got {}",
            entry.next_attempt_at
        );
        assert_eq!(entry.last_error.as_deref(), Some("connection refused"));

        // Second failure: attempt_count was 1, base = 30 * 2^1 = 60, ±20% → [48, 72].
        let now2 = entry.next_attempt_at;
        let entries2 = ob.get_by_message("msg-3").unwrap();
        ob.record_failure(&entries2[0], "timeout", now2).unwrap();
        let entries3 = ob.get_by_message("msg-3").unwrap();
        assert!(!entries3.is_empty(), "still in outbox after second failure");
        let entry2 = &entries3[0];
        assert_eq!(entry2.attempt_count, 2);
        assert!(
            entry2.next_attempt_at >= now2 + 48 && entry2.next_attempt_at <= now2 + 72,
            "second failure: next_attempt_at must be in [now2+48, now2+72], got {}",
            entry2.next_attempt_at
        );
    }

    #[test]
    fn mark_delivered_removes_outbox_row() {
        // Oracle: DELETE removes the row; get_by_message returns empty Vec afterward.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-4");

        let ob = store.outbox();
        ob.enqueue("msg-4", "user-b", "host-b.example.ts.net", 1000)
            .unwrap();
        let entries = ob.get_by_message("msg-4").unwrap();
        ob.mark_delivered(&entries[0]).unwrap();

        let entries = ob.get_by_message("msg-4").unwrap();
        assert!(
            entries.is_empty(),
            "outbox row must be gone after mark_delivered"
        );
    }

    #[test]
    fn complete_delivery_advances_state_and_removes_outbox_row() {
        // Oracle: complete_delivery must atomically (a) delete the outbox row,
        // (b) set delivery_state='delivered' and delivered_at, and (c) advance the
        // message state counter so get_changes_since returns the message.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-cd");

        let ob = store.outbox();
        ob.enqueue("msg-cd", "user-b", "host-b.example.ts.net", 1000)
            .unwrap();

        let ms = crate::message::MessageStore::new(&store.conn, None);
        let state_before = ms.get_state().unwrap();

        let entries = ob.get_by_message("msg-cd").unwrap();
        ob.complete_delivery(&entries[0], 2000).unwrap();

        // Outbox row must be gone.
        assert!(
            ob.get_by_message("msg-cd").unwrap().is_empty(),
            "outbox row must be deleted after complete_delivery"
        );

        // delivery_state and delivered_at must be updated.
        let (state, delivered_at): (String, Option<i64>) = store
            .conn
            .query_row(
                "SELECT delivery_state, delivered_at FROM messages WHERE id = 'msg-cd'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, "delivered");
        assert_eq!(delivered_at, Some(2000));

        // State counter must have advanced so get_changes_since returns this message.
        // The message existed before state_before (it was inserted first), so it
        // must appear in updated[] per RFC 8620 §5.2, not added[].
        let changes = ms.get_changes_since(&state_before).unwrap();
        assert!(
            changes.updated.contains(&"msg-cd".to_string()),
            "complete_delivery must advance state_version so the message appears \
             in updated[] (RFC 8620 §5.2); updated={:?}",
            changes.updated
        );
    }

    #[test]
    fn record_failure_truncates_error_at_utf8_boundary() {
        // Oracle: error strings > 500 bytes are truncated at the last UTF-8 char boundary
        // so that no multi-byte character is split.
        //
        // Input: 499 ASCII 'x' + '€' (U+20AC, 3 bytes) + 4 ASCII 'y' = 506 bytes.
        // The '€' starts at byte index 499 (< 500) → included in output.
        // The 'y' chars start at byte index 502 (≥ 500) → excluded.
        // A naive &s[..500] would split '€' (panic); the code must avoid this.
        // Expected stored value: 499 'x' + '€' = 502 bytes, all valid UTF-8.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-trunc");

        let ob = store.outbox();
        ob.enqueue("msg-trunc", "user-b", "host-b.example.ts.net", 1000)
            .unwrap();

        let long_error = format!("{}{}{}", "x".repeat(499), '€', "yyyy");
        assert_eq!(
            long_error.len(),
            506,
            "precondition: input must be 506 bytes"
        );

        let entries = ob.get_by_message("msg-trunc").unwrap();
        ob.record_failure(&entries[0], &long_error, 1000).unwrap();

        let entries = ob.get_by_message("msg-trunc").unwrap();
        assert!(!entries.is_empty(), "still in outbox after one failure");
        let stored = entries[0]
            .last_error
            .as_deref()
            .expect("last_error must be set");

        // Must be valid UTF-8 (would panic on read if a byte sequence were split).
        assert!(
            std::str::from_utf8(stored.as_bytes()).is_ok(),
            "stored error must be valid UTF-8"
        );
        // Must end with '€' (last complete multi-byte char preserved).
        assert!(
            stored.ends_with('€'),
            "stored error must end with '€'; got: {stored:?}"
        );
        // Must not contain any 'y' (truncation excluded the chars after '€').
        assert!(
            !stored.contains('y'),
            "stored error must not contain 'y' after truncation; got: {stored:?}"
        );
        // Must be exactly 502 bytes (499 ASCII + 3-byte '€').
        assert_eq!(stored.len(), 502, "truncated length must be 502 bytes");
    }

    #[test]
    fn mark_failed_advances_message_state_counter() {
        // Oracle: after mark_failed, get_changes_since(state_before) must include the
        // message in `updated` (not `added`).  The message was inserted before state_before
        // was captured, so it existed before sinceState — RFC 8620 §5.2 requires it in
        // updated[], not created[].  This verifies that mark_failed advances state_version
        // on the messages row so the JMAP polling path is not blind to permanent failures.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-mf");

        let ob = store.outbox();
        ob.enqueue("msg-mf", "user-b", "host-b.example.ts.net", 1000)
            .unwrap();

        let ms = crate::message::MessageStore::new(&store.conn, None);
        let state_before = ms.get_state().unwrap();

        let entries = ob.get_by_message("msg-mf").unwrap();
        ob.mark_failed(&entries[0], "permanent error").unwrap();

        let changes = ms.get_changes_since(&state_before).unwrap();
        assert!(
            changes.updated.contains(&"msg-mf".to_string()),
            "mark_failed must advance message state_version so get_changes_since returns it \
             in updated[] (RFC 8620 §5.2); updated={:?}",
            changes.updated
        );
    }

    #[test]
    fn seventy_second_failure_triggers_mark_failed() {
        // Oracle: after 72 failures (attempt_count reaches 71 before the 72nd call),
        // delivery_state must be 'failed' in messages and the outbox row must be deleted.
        // Attempt 71 (0-indexed) must NOT yet trigger mark_failed.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-5");

        let ob = store.outbox();
        let mut now: i64 = 1000;
        ob.enqueue("msg-5", "user-b", "host-b.example.ts.net", now)
            .unwrap();

        // Drive 71 failures — row must still exist after each.
        // Advance by 5000s per call: exceeds the maximum possible delay
        // (3600s base × 1.2 jitter = 4320s) so that get_due would return the entry.
        for i in 0..71u32 {
            let entries = ob.get_by_message("msg-5").unwrap();
            assert!(
                !entries.is_empty(),
                "outbox row must exist before failure {}",
                i + 1
            );
            ob.record_failure(&entries[0], "repeated error", now)
                .unwrap();
            now += 5000;
        }

        // Verify row still exists after 71 failures (not yet mark_failed).
        assert!(
            !ob.get_by_message("msg-5").unwrap().is_empty(),
            "outbox row must still exist after 71 failures"
        );

        // 72nd failure triggers mark_failed.
        let entries = ob.get_by_message("msg-5").unwrap();
        ob.record_failure(&entries[0], "final error", now).unwrap();

        // Outbox row must be gone.
        let entries = ob.get_by_message("msg-5").unwrap();
        assert!(
            entries.is_empty(),
            "outbox row must be deleted after 72 failures"
        );

        // messages.delivery_state must be 'failed'.
        let state: String = store
            .conn
            .query_row(
                "SELECT delivery_state FROM messages WHERE id = 'msg-5'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            state, "failed",
            "delivery_state must be 'failed' after 72 failures"
        );
    }

    #[test]
    fn enqueue_receipt_creates_receipt_kind_row() {
        // Oracle: enqueue_receipt inserts a row with kind='receipt' and read_at_unix set.
        // get_by_message returns it; get_due returns it when due.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-rcpt");

        let ob = store.outbox();
        ob.enqueue_receipt("msg-rcpt", "user-b", "host-b.example.ts.net", 9999, 1000)
            .unwrap();

        let entries = ob.get_by_message("msg-rcpt").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, "receipt");
        assert_eq!(entries[0].read_at_unix, Some(9999));
        assert_eq!(entries[0].next_attempt_at, 1000);
        assert_eq!(entries[0].attempt_count, 0);

        // get_due must return it at now_unix=1000.
        let due = ob.get_due(1000).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].kind, "receipt");
    }

    #[test]
    fn complete_delivery_receipt_only_deletes_outbox_row() {
        // Oracle: for kind='receipt', complete_delivery must only delete the outbox row.
        // It must NOT update messages.delivery_state or advance the state counter.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-rcpt-cd");

        let ob = store.outbox();
        ob.enqueue_receipt("msg-rcpt-cd", "user-b", "host-b.example.ts.net", 9999, 1000)
            .unwrap();

        let ms = crate::message::MessageStore::new(&store.conn, None);
        let state_before = ms.get_state().unwrap();

        let entries = ob.get_by_message("msg-rcpt-cd").unwrap();
        ob.complete_delivery(&entries[0], 1000).unwrap();

        // Outbox row must be gone.
        assert!(
            ob.get_by_message("msg-rcpt-cd").unwrap().is_empty(),
            "outbox row must be deleted after complete_delivery on receipt"
        );

        // delivery_state must remain 'pending' (not touched for receipts).
        let state: String = store
            .conn
            .query_row(
                "SELECT delivery_state FROM messages WHERE id = 'msg-rcpt-cd'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            state, "pending",
            "delivery_state must remain 'pending' after receipt complete_delivery"
        );

        // State counter must NOT have advanced.
        let changes = ms.get_changes_since(&state_before).unwrap();
        assert!(
            !changes.added.contains(&"msg-rcpt-cd".to_string()),
            "receipt complete_delivery must not advance state counter; added={:?}",
            changes.added
        );
    }

    #[test]
    fn complete_delivery_nonexistent_message_does_not_advance_counter() {
        // Oracle: if the message row referenced by the outbox entry does not exist,
        // complete_delivery must NOT advance the state counter.  It must still delete
        // the outbox row (orphaned entry cleanup).
        // Independent oracle: state counter read before and after must be equal.
        //
        // Setup: insert the outbox row with FK enforcement OFF so that no messages
        // row is needed.  This simulates an orphaned outbox entry (e.g. the message
        // row was hard-deleted outside normal application flow).
        let store = Store::open_in_memory().unwrap();

        store
            .conn
            .execute_batch("PRAGMA foreign_keys = OFF")
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO outbox \
                 (message_id, peer_user_id, peer_mailbox_host, kind, next_attempt_at, attempt_count) \
                 VALUES ('msg-no-row', 'user-b', 'host-b.example.ts.net', 'message', 1000, 0)",
                [],
            )
            .unwrap();
        store
            .conn
            .execute_batch("PRAGMA foreign_keys = ON")
            .unwrap();

        let ms = crate::message::MessageStore::new(&store.conn, None);
        let state_before = ms.get_state().unwrap();

        let ob = store.outbox();
        let entries = ob.get_by_message("msg-no-row").unwrap();
        assert_eq!(entries.len(), 1, "orphaned outbox entry must be present");
        ob.complete_delivery(&entries[0], 2000).unwrap();

        // Outbox row must be gone (cleanup succeeded).
        assert!(
            ob.get_by_message("msg-no-row").unwrap().is_empty(),
            "orphaned outbox row must be deleted by complete_delivery"
        );

        // State counter must NOT have advanced — the UPDATE found no message row.
        let state_after = ms.get_state().unwrap();
        assert_eq!(
            state_before, state_after,
            "state counter must not advance when complete_delivery finds no message row"
        );
    }

    #[test]
    fn enqueue_is_idempotent() {
        // Oracle: the outbox PRIMARY KEY is (message_id, peer_user_id, kind).
        // Calling enqueue() twice with the same (message_id, peer_user_id) must:
        //   - succeed on both calls (no error)
        //   - leave exactly one row in outbox for that message
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-idem");

        let ob = store.outbox();

        ob.enqueue("msg-idem", "user-b", "host-b.example.ts.net", 1000)
            .expect("first enqueue must succeed");

        ob.enqueue("msg-idem", "user-b", "host-b.example.ts.net", 1000)
            .expect("second enqueue with same args must succeed (idempotent)");

        let entries = ob.get_by_message("msg-idem").unwrap();
        assert_eq!(
            entries.len(),
            1,
            "outbox must contain exactly one row after two identical enqueue calls"
        );
    }

    #[test]
    fn mark_failed_receipt_only_deletes_outbox_row() {
        // Oracle: for kind='receipt', mark_failed must only delete the outbox row.
        // It must NOT update messages.delivery_state or advance the state counter.
        let store = Store::open_in_memory().unwrap();
        insert_test_message(&store.conn, "msg-rcpt-mf");

        let ob = store.outbox();
        ob.enqueue_receipt("msg-rcpt-mf", "user-b", "host-b.example.ts.net", 9999, 1000)
            .unwrap();

        let ms = crate::message::MessageStore::new(&store.conn, None);
        let state_before = ms.get_state().unwrap();

        let entries = ob.get_by_message("msg-rcpt-mf").unwrap();
        ob.mark_failed(&entries[0], "permanent error").unwrap();

        // Outbox row must be gone.
        assert!(
            ob.get_by_message("msg-rcpt-mf").unwrap().is_empty(),
            "outbox row must be deleted after mark_failed on receipt"
        );

        // delivery_state must remain 'pending'.
        let state: String = store
            .conn
            .query_row(
                "SELECT delivery_state FROM messages WHERE id = 'msg-rcpt-mf'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            state, "pending",
            "delivery_state must remain 'pending' after receipt mark_failed"
        );

        // State counter must NOT have advanced.
        let changes = ms.get_changes_since(&state_before).unwrap();
        assert!(
            !changes.added.contains(&"msg-rcpt-mf".to_string()),
            "receipt mark_failed must not advance state counter; added={:?}",
            changes.added
        );
    }
}
