use serde::{Deserialize, Serialize};

/// Authorization role derived from WhoIs on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Peer,
}

/// Verified caller identity from Tailscale LocalAPI WhoIs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    /// Opaque stable key from Tailscale identity provider.
    /// Never parse or assume format. Compare with == only.
    pub user_id: String,
    /// Email-shaped login (e.g. "alice@example.com") or bare username.
    /// May be empty on Headscale without OIDC.
    pub login_name: String,
    /// User-visible display name. May be absent or empty.
    pub display_name: Option<String>,
    /// MagicDNS hostname of the caller's Tailscale node. From WhoIs node.name.
    /// Used to bootstrap peer_mailbox_host in ContactStore. May be empty on
    /// Headscale without node names configured; callers must handle empty.
    pub node_name: String,
}

impl Identity {
    /// Returns the best available display string for this identity.
    /// Falls back: display_name → login_name → user_id.
    /// Never returns an empty string.
    pub fn display(&self) -> &str {
        if let Some(name) = &self.display_name {
            if !name.is_empty() {
                return name.as_str();
            }
        }
        if !self.login_name.is_empty() {
            return self.login_name.as_str();
        }
        &self.user_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Role::Owner).unwrap(), r#""owner""#);
        assert_eq!(serde_json::to_string(&Role::Peer).unwrap(), r#""peer""#);
    }

    #[test]
    fn role_deserializes_lowercase() {
        assert_eq!(
            serde_json::from_str::<Role>(r#""owner""#).unwrap(),
            Role::Owner
        );
        assert_eq!(
            serde_json::from_str::<Role>(r#""peer""#).unwrap(),
            Role::Peer
        );
    }

    #[test]
    fn identity_display_uses_display_name() {
        let id = Identity {
            user_id: "uid-123".into(),
            login_name: "alice@example.com".into(),
            display_name: Some("Alice Smith".into()),
            node_name: "alice-node.tail12345.ts.net".into(),
        };
        assert_eq!(id.display(), "Alice Smith");
    }

    #[test]
    fn identity_display_falls_back_to_login() {
        let id = Identity {
            user_id: "uid-123".into(),
            login_name: "alice@example.com".into(),
            display_name: None,
            node_name: "alice-node.tail12345.ts.net".into(),
        };
        assert_eq!(id.display(), "alice@example.com");
    }

    #[test]
    fn identity_display_falls_back_to_user_id() {
        let id = Identity {
            user_id: "uid-123".into(),
            login_name: String::new(),
            display_name: None,
            node_name: "alice-node.tail12345.ts.net".into(),
        };
        assert_eq!(id.display(), "uid-123");
    }

    #[test]
    fn identity_display_ignores_empty_display_name() {
        let id = Identity {
            user_id: "uid-123".into(),
            login_name: "alice@example.com".into(),
            display_name: Some(String::new()),
            node_name: "alice-node.tail12345.ts.net".into(),
        };
        assert_eq!(id.display(), "alice@example.com");
    }

    #[test]
    fn identity_round_trip() {
        let id = Identity {
            user_id: "uid-123".into(),
            login_name: "alice@example.com".into(),
            display_name: Some("Alice".into()),
            node_name: "alice-node.tail12345.ts.net".into(),
        };
        let json = serde_json::to_string(&id).unwrap();
        let id2: Identity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }
}
