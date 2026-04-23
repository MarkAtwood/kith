use serde::{Deserialize, Serialize};

/// A contact known to this mailbox.
/// Auto-created on first inbound delivery or manually by owner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatContact {
    /// Server-assigned opaque identifier.
    pub id: String,
    /// Opaque stable key from Tailscale identity provider.
    /// Never parse or assume format. Compare with == only.
    #[serde(rename = "tailscaleUserId")]
    pub tailscale_user_id: String,
    /// Email-shaped login (e.g. "alice@example.com"). May be empty on Headscale.
    pub login: String,
    /// MagicDNS hostname of the contact's mailbox (e.g. "alice-kith.tail-xxxxx.ts.net").
    #[serde(rename = "mailboxHost")]
    pub mailbox_host: String,
    /// User-editable display name. Falls back to login or tailscale_user_id if absent.
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// When this contact was first seen (RFC 3339 UTC).
    #[serde(rename = "firstSeenAt")]
    pub first_seen_at: String,
    /// When this contact was last seen (RFC 3339 UTC).
    #[serde(rename = "lastSeenAt")]
    pub last_seen_at: String,
    /// Whether this contact is blocked. Blocked contacts cannot deliver messages.
    pub blocked: bool,
}

impl ChatContact {
    /// Returns the best available display string for this contact.
    /// Falls back: display_name → login → tailscale_user_id.
    /// Never returns an empty string.
    pub fn display_name_or_fallback(&self) -> &str {
        if let Some(name) = &self.display_name {
            if !name.is_empty() {
                return name.as_str();
            }
        }
        if !self.login.is_empty() {
            return self.login.as_str();
        }
        &self.tailscale_user_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contact() -> ChatContact {
        ChatContact {
            id: "c-001".into(),
            tailscale_user_id: "uid-456".into(),
            login: "bob@example.com".into(),
            mailbox_host: "bob-kith.tail-yyyyy.ts.net".into(),
            display_name: Some("Bob Smith".into()),
            first_seen_at: "2026-01-01T00:00:00Z".into(),
            last_seen_at: "2026-04-18T20:14:00Z".into(),
            blocked: false,
        }
    }

    #[test]
    fn contact_round_trip() {
        let c = sample_contact();
        let json_str = serde_json::to_string(&c).unwrap();
        let c2: ChatContact = serde_json::from_str(&json_str).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn contact_json_field_names_are_camel_case() {
        let c = sample_contact();
        let json_str = serde_json::to_string(&c).unwrap();
        assert!(
            json_str.contains("\"tailscaleUserId\""),
            "must use camelCase tailscaleUserId"
        );
        assert!(
            json_str.contains("\"mailboxHost\""),
            "must use camelCase mailboxHost"
        );
        assert!(
            json_str.contains("\"firstSeenAt\""),
            "must use camelCase firstSeenAt"
        );
        assert!(
            json_str.contains("\"lastSeenAt\""),
            "must use camelCase lastSeenAt"
        );
        assert!(
            json_str.contains("\"displayName\""),
            "must use camelCase displayName"
        );
        assert!(!json_str.contains("\"tailscale_user_id\""));
    }

    #[test]
    fn contact_none_display_name_is_omitted() {
        let mut c = sample_contact();
        c.display_name = None;
        let json_str = serde_json::to_string(&c).unwrap();
        assert!(
            !json_str.contains("\"displayName\""),
            "None displayName must be omitted"
        );
    }

    #[test]
    fn display_name_or_fallback_uses_display_name() {
        let c = sample_contact();
        assert_eq!(c.display_name_or_fallback(), "Bob Smith");
    }

    #[test]
    fn display_name_or_fallback_uses_login() {
        let mut c = sample_contact();
        c.display_name = None;
        assert_eq!(c.display_name_or_fallback(), "bob@example.com");
    }

    #[test]
    fn display_name_or_fallback_uses_user_id() {
        let mut c = sample_contact();
        c.display_name = None;
        c.login = String::new();
        assert_eq!(c.display_name_or_fallback(), "uid-456");
    }

    #[test]
    fn display_name_or_fallback_ignores_empty_display_name() {
        let mut c = sample_contact();
        c.display_name = Some(String::new());
        assert_eq!(c.display_name_or_fallback(), "bob@example.com");
    }

    #[test]
    fn blocked_serializes_as_bool() {
        let c = sample_contact();
        let json_str = serde_json::to_string(&c).unwrap();
        assert!(json_str.contains("\"blocked\":false"));
    }
}
