use serde::{Deserialize, Serialize};

/// Message delivery state.
/// Outgoing: pending → delivered (or failed).
/// Incoming: always received.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// Outgoing: not yet delivered to recipient mailbox.
    Pending,
    /// Outgoing: recipient mailbox accepted via Peer/deliver.
    Delivered,
    /// Outgoing: delivery failed after all retries.
    Failed,
    /// Incoming: stored by this mailbox.
    Received,
}

/// Attachment metadata (bytes live at the download URL, not in this struct).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// Opaque blob identifier used in download URL template.
    /// MUST be validated (no path traversal) before use in filesystem paths.
    #[serde(rename = "blobId")]
    pub blob_id: String,
    /// User-visible filename.
    /// MUST be sanitized (no "../", absolute paths, null bytes) before filesystem use.
    pub filename: String,
    /// MIME type string (e.g. "image/png"). Must be validated as legal MIME.
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// Size in bytes. Must be verified against actual received bytes.
    pub size: u64,
    /// Hex-encoded SHA-256 of the blob. Computed server-side; verify against received bytes.
    pub sha256: String,
}

/// A chat message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// ULID — time-sortable unique identifier.
    pub id: String,
    /// Deterministic chat identifier.
    #[serde(rename = "chatId")]
    pub chat_id: String,
    /// Contact id of sender, or "self" for outgoing messages.
    #[serde(rename = "senderId")]
    pub sender_id: String,
    /// Message body text (UTF-8). Must be ≤ maxBodyBytes (65536) at boundary.
    pub body: String,
    /// Body MIME type. Must be "text/plain" or "text/markdown".
    #[serde(rename = "bodyType")]
    pub body_type: String,
    /// Attachment metadata. May be empty.
    pub attachments: Vec<Attachment>,
    /// Optional reference to another message in the same chat.
    /// Must be validated (referenced message exists, same chat) before storage.
    #[serde(rename = "replyTo", skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Sender's clock timestamp (RFC 3339 UTC). UNTRUSTED — display only.
    /// Do NOT use for message ordering.
    #[serde(rename = "sentAt")]
    pub sent_at: String,
    /// Receiver's clock timestamp (RFC 3339 UTC). TRUSTED — authoritative for ordering.
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    /// Delivery state. Set server-side; do not trust peer-supplied value.
    #[serde(rename = "deliveryState")]
    pub delivery_state: DeliveryState,
    /// When delivery to recipient succeeded (outgoing only).
    #[serde(rename = "deliveredAt", skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<String>,
    /// When the owner marked this message as read.
    #[serde(rename = "readAt", skip_serializing_if = "Option::is_none")]
    pub read_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attachment() -> Attachment {
        Attachment {
            blob_id: "blob-abc123".into(),
            filename: "photo.png".into(),
            content_type: "image/png".into(),
            size: 102400,
            sha256: "a".repeat(64),
        }
    }

    fn sample_message() -> Message {
        Message {
            id: "01JVWXYZ0000000000000000AB".into(),
            chat_id: "deadbeef".repeat(8),
            sender_id: "c-001".into(),
            body: "Hello, world!".into(),
            body_type: "text/plain".into(),
            attachments: vec![],
            reply_to: None,
            sent_at: "2026-04-18T20:00:00Z".into(),
            received_at: "2026-04-18T20:00:01Z".into(),
            delivery_state: DeliveryState::Received,
            delivered_at: None,
            read_at: None,
        }
    }

    #[test]
    fn delivery_state_serializes_snake_case() {
        // Independent oracle: spec says values are "pending", "delivered", "failed", "received"
        assert_eq!(
            serde_json::to_string(&DeliveryState::Pending).unwrap(),
            r#""pending""#
        );
        assert_eq!(
            serde_json::to_string(&DeliveryState::Delivered).unwrap(),
            r#""delivered""#
        );
        assert_eq!(
            serde_json::to_string(&DeliveryState::Failed).unwrap(),
            r#""failed""#
        );
        assert_eq!(
            serde_json::to_string(&DeliveryState::Received).unwrap(),
            r#""received""#
        );
    }

    #[test]
    fn delivery_state_round_trip() {
        for state in [
            DeliveryState::Pending,
            DeliveryState::Delivered,
            DeliveryState::Failed,
            DeliveryState::Received,
        ] {
            let json_str = serde_json::to_string(&state).unwrap();
            let s2: DeliveryState = serde_json::from_str(&json_str).unwrap();
            assert_eq!(state, s2);
        }
    }

    #[test]
    fn attachment_round_trip() {
        let a = sample_attachment();
        let json_str = serde_json::to_string(&a).unwrap();
        let a2: Attachment = serde_json::from_str(&json_str).unwrap();
        assert_eq!(a, a2);
    }

    #[test]
    fn attachment_json_field_names() {
        let a = sample_attachment();
        let json_str = serde_json::to_string(&a).unwrap();
        assert!(json_str.contains("\"blobId\""));
        assert!(json_str.contains("\"contentType\""));
        assert!(!json_str.contains("\"blob_id\""));
        assert!(!json_str.contains("\"content_type\""));
    }

    #[test]
    fn message_round_trip() {
        let m = sample_message();
        let json_str = serde_json::to_string(&m).unwrap();
        let m2: Message = serde_json::from_str(&json_str).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn message_json_field_names_camel_case() {
        let m = sample_message();
        let json_str = serde_json::to_string(&m).unwrap();
        assert!(json_str.contains("\"chatId\""));
        assert!(json_str.contains("\"senderId\""));
        assert!(json_str.contains("\"bodyType\""));
        assert!(json_str.contains("\"sentAt\""));
        assert!(json_str.contains("\"receivedAt\""));
        assert!(json_str.contains("\"deliveryState\""));
    }

    #[test]
    fn message_optional_fields_omitted_when_none() {
        let m = sample_message(); // reply_to, delivered_at, read_at all None
        let json_str = serde_json::to_string(&m).unwrap();
        assert!(
            !json_str.contains("\"replyTo\""),
            "None replyTo must be omitted"
        );
        assert!(
            !json_str.contains("\"deliveredAt\""),
            "None deliveredAt must be omitted"
        );
        assert!(
            !json_str.contains("\"readAt\""),
            "None readAt must be omitted"
        );
    }

    #[test]
    fn message_with_attachment_round_trip() {
        let mut m = sample_message();
        m.attachments = vec![sample_attachment()];
        let json_str = serde_json::to_string(&m).unwrap();
        let m2: Message = serde_json::from_str(&json_str).unwrap();
        assert_eq!(m, m2);
        assert_eq!(m2.attachments.len(), 1);
    }
}
