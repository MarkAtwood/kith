use serde::{Deserialize, Serialize};

/// A chat session between two or more participants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chat {
    /// Server-assigned ULID. Stable for the lifetime of the chat.
    pub id: String,
    /// "direct" for 1:1, "group" for N-way.
    pub kind: String,
    /// For direct chats: the peer contact's userId. None for group chats.
    #[serde(rename = "contactId", skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
    /// When this chat was created (RFC 3339 UTC).
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// When the most recent message was received (RFC 3339 UTC). Null if no messages.
    #[serde(rename = "lastMessageAt", skip_serializing_if = "Option::is_none")]
    pub last_message_at: Option<String>,
    /// Unread message count. Computed server-side from read cursor; not persisted.
    #[serde(rename = "unreadCount")]
    pub unread_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_chat() -> Chat {
        Chat {
            id: "01JVTESTCHATID000000000001".into(),
            kind: "direct".into(),
            contact_id: Some("uid-bob".into()),
            created_at: "2026-01-01T00:00:00Z".into(),
            last_message_at: Some("2026-04-18T20:14:00Z".into()),
            unread_count: 3,
        }
    }

    #[test]
    fn chat_round_trip() {
        let c = sample_chat();
        let json_str = serde_json::to_string(&c).unwrap();
        let c2: Chat = serde_json::from_str(&json_str).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn chat_json_field_names() {
        let c = sample_chat();
        let json_str = serde_json::to_string(&c).unwrap();
        assert!(json_str.contains("\"createdAt\""));
        assert!(json_str.contains("\"unreadCount\""));
        assert!(json_str.contains("\"contactId\""));
        assert!(!json_str.contains("\"created_at\""));
        assert!(
            !json_str.contains("\"last_message_at\""),
            "None lastMessageAt must be omitted"
        );
        assert!(
            !json_str.contains("\"participants\""),
            "participants field must not appear (removed in I-D alignment)"
        );
    }

    #[test]
    fn chat_none_contact_id_omitted() {
        let mut c = sample_chat();
        c.contact_id = None;
        let json_str = serde_json::to_string(&c).unwrap();
        assert!(
            !json_str.contains("\"contactId\""),
            "None contactId must be omitted"
        );
    }
}
