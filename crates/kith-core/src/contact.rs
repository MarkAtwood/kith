use serde::{Deserialize, Serialize};

/// A contact known to this mailbox.
///
/// `id` is the stable, opaque userId provided by the authentication layer —
/// the same value used as `senderUserId` in `Peer/deliver`. It is the single
/// identity key for this contact within this deployment. Never parse it or
/// assume a format; compare with `==` only.
///
/// `mailboxHost` is intentionally absent: it is a delivery-routing detail
/// stored in the DB layer (see `ContactStore::get_mailbox_host`) but not
/// exposed in the JMAP ChatContact type per the I-D.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatContact {
    /// The userId provided by the authentication layer.
    /// This IS the identity — there is no separate identity namespace.
    pub id: String,
    /// Human-readable login identifier. Falls back to `id` when `displayName` is absent.
    pub login: String,
    /// User-editable display name. Falls back to `login`, then `id` if absent or empty.
    #[serde(rename = "displayName", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// When this contact was first recorded (RFC 3339 UTC).
    #[serde(rename = "firstSeenAt")]
    pub first_seen_at: String,
    /// Time of most recent interaction with this contact's mailbox (RFC 3339 UTC).
    #[serde(rename = "lastSeenAt")]
    pub last_seen_at: String,
    /// When `true`, messages from this contact are silently dropped.
    pub blocked: bool,
}

impl ChatContact {
    /// Returns the best available display string for this contact.
    /// Falls back: display_name → login → id. Never returns an empty string.
    pub fn display_name_or_fallback(&self) -> &str {
        if let Some(name) = &self.display_name {
            if !name.is_empty() {
                return name.as_str();
            }
        }
        if !self.login.is_empty() {
            return self.login.as_str();
        }
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_contact() -> ChatContact {
        ChatContact {
            id: "uid-456".into(),
            login: "bob@example.com".into(),
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
        // Oracle: I-D §ChatContact — field names are camelCase per JMAP convention.
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
        // tailscaleUserId and mailboxHost must NOT appear — they were removed in I-D alignment.
        assert!(
            !json_str.contains("tailscaleUserId"),
            "tailscaleUserId must not be serialized"
        );
        assert!(
            !json_str.contains("mailboxHost"),
            "mailboxHost must not be serialized"
        );
        assert!(
            !json_str.contains("tailscale_user_id"),
            "snake_case must not appear"
        );
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
    fn display_name_or_fallback_uses_id() {
        // Oracle: when both displayName and login are absent/empty, fall back to id.
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
