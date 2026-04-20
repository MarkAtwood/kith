use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A chat session between two or more participants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chat {
    /// Deterministic ID: hex(sha256(sorted_tailscale_user_ids joined by \x00)).
    /// Both participants compute the same ID without coordination.
    pub id: String,
    /// "direct" for 1:1, "group" for N-way.
    pub kind: String,
    /// Contact ids of participants. Excludes self for direct chats.
    pub participants: Vec<String>,
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

/// Compute the deterministic chat ID for a set of participant Tailscale user IDs.
///
/// Algorithm:
/// 1. Sort participant IDs lexicographically (byte order, Rust default for &str).
/// 2. Join with a single null byte (0x00) separator.
/// 3. SHA-256 hash the joined bytes.
/// 4. Hex-encode the 32-byte result (lowercase).
///
/// Both mailboxes call this with the same set of IDs and get the same result.
/// CRITICAL: never trust a peer-supplied chatId — always recompute and compare.
pub fn compute_chat_id<S: AsRef<str>>(participant_ids: &[S]) -> String {
    let mut sorted: Vec<&str> = participant_ids.iter().map(|s| s.as_ref()).collect();
    // Sort is byte-lexicographic for &str in Rust, which is deterministic across platforms.
    sorted.sort();

    let mut hasher = Sha256::new();
    for (i, id) in sorted.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\x00");
        }
        hasher.update(id.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors computed independently using Python 3:
    //
    //   import hashlib
    //
    //   # Two-participant case
    //   ids = sorted(["uid:alice@example.com", "uid:bob@example.com"])
    //   data = "\x00".join(ids).encode()
    //   print(hashlib.sha256(data).hexdigest())
    //   # => 4e65c0c75c3c4e9cf6ec2a02edf4b65ba5e985d352f2d6e40a153a11f13f3c82
    //
    //   # Single-participant case
    //   data2 = "uid:alice@example.com".encode()
    //   print(hashlib.sha256(data2).hexdigest())
    //   # => 8591f893f06491cc56214b506c26e3b2958dead131cb67e3f56642880f5462c4

    #[test]
    fn compute_chat_id_two_participants() {
        let result = compute_chat_id(&["uid:alice@example.com", "uid:bob@example.com"]);
        assert_eq!(
            result,
            "4e65c0c75c3c4e9cf6ec2a02edf4b65ba5e985d352f2d6e40a153a11f13f3c82"
        );
    }

    #[test]
    fn compute_chat_id_order_independent() {
        let id1 = compute_chat_id(&["uid:alice@example.com", "uid:bob@example.com"]);
        let id2 = compute_chat_id(&["uid:bob@example.com", "uid:alice@example.com"]);
        assert_eq!(
            id1, id2,
            "chat ID must be order-independent (both parties agree)"
        );
    }

    #[test]
    fn compute_chat_id_single_participant() {
        let result = compute_chat_id(&["uid:alice@example.com"]);
        assert_eq!(
            result,
            "8591f893f06491cc56214b506c26e3b2958dead131cb67e3f56642880f5462c4"
        );
    }

    #[test]
    fn compute_chat_id_different_participants_differ() {
        let id1 = compute_chat_id(&["uid:alice@example.com", "uid:bob@example.com"]);
        let id2 = compute_chat_id(&["uid:alice@example.com", "uid:carol@example.com"]);
        assert_ne!(
            id1, id2,
            "different participant sets must produce different IDs"
        );
    }

    #[test]
    fn chat_round_trip() {
        let c = Chat {
            id: compute_chat_id(&["uid:alice@example.com", "uid:bob@example.com"]),
            kind: "direct".into(),
            participants: vec!["c-001".into()],
            created_at: "2026-01-01T00:00:00Z".into(),
            last_message_at: Some("2026-04-18T20:14:00Z".into()),
            unread_count: 3,
        };
        let json_str = serde_json::to_string(&c).unwrap();
        let c2: Chat = serde_json::from_str(&json_str).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn chat_json_field_names() {
        let c = Chat {
            id: "abc".into(),
            kind: "direct".into(),
            participants: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            last_message_at: None,
            unread_count: 0,
        };
        let json_str = serde_json::to_string(&c).unwrap();
        assert!(json_str.contains("\"createdAt\""));
        assert!(json_str.contains("\"unreadCount\""));
        assert!(!json_str.contains("\"created_at\""));
        assert!(
            !json_str.contains("\"last_message_at\""),
            "None lastMessageAt must be omitted"
        );
    }
}
