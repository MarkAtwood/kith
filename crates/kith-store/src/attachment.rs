use crate::db_err;
use kith_core::{Attachment, KithError};
use rusqlite::{params, Connection};

pub struct AttachmentStore<'a> {
    conn: &'a Connection,
}

impl<'a> AttachmentStore<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        AttachmentStore { conn }
    }

    /// Insert an attachment metadata row.
    ///
    /// `blob_id` is the primary key (the `id` column in the `attachments` table).
    /// `size_bytes` is stored as i64 in SQLite; returns an error if the value exceeds i64::MAX.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        blob_id: &str,
        message_id: &str,
        filename: &str,
        content_type: &str,
        size_bytes: u64,
        sha256: &str,
        now_unix: i64,
    ) -> Result<(), KithError> {
        self.conn
            .execute(
                "INSERT INTO attachments \
                    (id, message_id, filename, content_type, size_bytes, sha256, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    blob_id,
                    message_id,
                    filename,
                    content_type,
                    i64::try_from(size_bytes).map_err(|_| KithError::Store(
                        "attachment too large: size exceeds i64::MAX".into()
                    ))?,
                    sha256,
                    now_unix,
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Fetch a single attachment by blob_id.  Returns `None` if not found.
    pub fn get(&self, blob_id: &str) -> Result<Option<Attachment>, KithError> {
        let result = self.conn.query_row(
            "SELECT id, filename, content_type, size_bytes, sha256 \
             FROM attachments WHERE id = ?1",
            params![blob_id],
            row_to_attachment,
        );
        match result {
            Ok(a) => Ok(Some(a)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err(e)),
        }
    }

    /// Return all attachments for a given message, ordered by `created_at`.
    pub fn list_by_message(&self, message_id: &str) -> Result<Vec<Attachment>, KithError> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id, filename, content_type, size_bytes, sha256 \
                 FROM attachments WHERE message_id = ?1 ORDER BY created_at",
            )
            .map_err(db_err)?;
        let attachments: Result<Vec<Attachment>, rusqlite::Error> = stmt
            .query_map(params![message_id], row_to_attachment)
            .map_err(db_err)?
            .collect();
        attachments.map_err(db_err)
    }

    /// Delete all attachment rows for a given message.
    ///
    /// Note: the `attachments` table has `ON DELETE CASCADE` on `message_id`,
    /// so deleting the message row will also remove attachments automatically.
    /// This method allows explicit removal without deleting the message.
    pub fn delete_by_message(&self, message_id: &str) -> Result<(), KithError> {
        self.conn
            .execute(
                "DELETE FROM attachments WHERE message_id = ?1",
                params![message_id],
            )
            .map_err(db_err)?;
        Ok(())
    }
}

/// Map a rusqlite Row to an Attachment.  Column order must match the SELECT above.
fn row_to_attachment(row: &rusqlite::Row<'_>) -> rusqlite::Result<Attachment> {
    let blob_id: String = row.get(0)?;
    let filename: String = row.get(1)?;
    let content_type: String = row.get(2)?;
    let size_bytes: i64 = row.get(3)?;
    // Negative means DB corruption; reject rather than clamp.
    if size_bytes < 0 {
        return Err(rusqlite::Error::IntegralValueOutOfRange(3, size_bytes));
    }
    let sha256: String = row.get(4)?;
    // Attachment is #[non_exhaustive]; construct via kith_core helper.
    Ok(kith_core::make_attachment(
        blob_id,
        filename,
        content_type,
        size_bytes as u64,
        sha256,
    ))
}

#[cfg(test)]
mod tests {
    use crate::Store;

    /// Insert the prerequisite chat and message rows required by FK constraints.
    fn insert_test_message(conn: &rusqlite::Connection) {
        conn.execute(
            "INSERT INTO chats (id, kind, created_at) VALUES ('chat-1', 'direct', 1000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages \
             (id, chat_id, sender_user_id, body, created_at, delivery_state, sender_msg_id) \
             VALUES ('msg-1', 'chat-1', 'user-a', 'hello', 1000, 'pending', 'msg-1')",
            [],
        )
        .unwrap();
    }

    #[test]
    fn insert_then_get_returns_correct_fields() {
        // Oracle: values are identical to what was inserted (no transformation
        // except u64 ↔ i64 cast for size_bytes, which is round-trip exact for
        // values below 2^63).
        let store = Store::open_in_memory().expect("open");
        insert_test_message(&store.conn);

        let as_ = store.attachments();
        as_.insert(
            "blob-abc",
            "msg-1",
            "photo.png",
            "image/png",
            4096,
            "a".repeat(64).as_str(),
            2000,
        )
        .unwrap();

        let a = as_.get("blob-abc").unwrap().expect("attachment must exist");
        assert_eq!(a.blob_id, "blob-abc");
        assert_eq!(a.filename, "photo.png");
        assert_eq!(a.content_type, "image/png");
        assert_eq!(a.size, 4096u64);
        assert_eq!(a.sha256, "a".repeat(64));
    }

    #[test]
    fn get_unknown_blob_id_returns_none() {
        let store = Store::open_in_memory().expect("open");
        let result = store.attachments().get("no-such-blob").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_by_message_returns_all_attachments() {
        // Oracle: two inserts for the same message; list must return both.
        let store = Store::open_in_memory().expect("open");
        insert_test_message(&store.conn);

        let as_ = store.attachments();
        as_.insert(
            "blob-1",
            "msg-1",
            "a.txt",
            "text/plain",
            10,
            "b".repeat(64).as_str(),
            1000,
        )
        .unwrap();
        as_.insert(
            "blob-2",
            "msg-1",
            "b.txt",
            "text/plain",
            20,
            "c".repeat(64).as_str(),
            2000,
        )
        .unwrap();

        let list = as_.list_by_message("msg-1").unwrap();
        assert_eq!(list.len(), 2);
        let ids: Vec<&str> = list.iter().map(|a| a.blob_id.as_ref()).collect();
        assert!(ids.contains(&"blob-1"));
        assert!(ids.contains(&"blob-2"));
    }

    #[test]
    fn list_by_message_unknown_message_returns_empty() {
        let store = Store::open_in_memory().expect("open");
        let list = store.attachments().list_by_message("no-such-msg").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn delete_by_message_removes_rows() {
        // Oracle: after delete_by_message, list_by_message must return empty vec.
        let store = Store::open_in_memory().expect("open");
        insert_test_message(&store.conn);

        let as_ = store.attachments();
        as_.insert(
            "blob-x",
            "msg-1",
            "x.bin",
            "application/octet-stream",
            99,
            "d".repeat(64).as_str(),
            1000,
        )
        .unwrap();

        let before = as_.list_by_message("msg-1").unwrap();
        assert_eq!(
            before.len(),
            1,
            "setup: must have one attachment before delete"
        );

        as_.delete_by_message("msg-1").unwrap();

        let after = as_.list_by_message("msg-1").unwrap();
        assert!(
            after.is_empty(),
            "list_by_message must return empty after delete_by_message"
        );
    }

    #[test]
    fn on_delete_cascade_removes_attachments_with_message() {
        // Oracle: the schema declares `message_id REFERENCES messages(id) ON DELETE CASCADE`.
        // Deleting the message row must cascade and remove all attachment rows.
        let store = Store::open_in_memory().expect("open");
        insert_test_message(&store.conn);

        let as_ = store.attachments();
        as_.insert(
            "blob-y",
            "msg-1",
            "y.pdf",
            "application/pdf",
            512,
            "e".repeat(64).as_str(),
            1000,
        )
        .unwrap();

        // Verify the attachment exists.
        assert!(as_.get("blob-y").unwrap().is_some());

        // Delete the parent message row.
        store
            .conn
            .execute("DELETE FROM messages WHERE id = 'msg-1'", [])
            .unwrap();

        // Cascade must have removed the attachment.
        let result = as_.get("blob-y").unwrap();
        assert!(
            result.is_none(),
            "ON DELETE CASCADE must remove attachment when message is deleted"
        );
    }
}
