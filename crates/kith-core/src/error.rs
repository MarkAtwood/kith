use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Authentication and authorization errors.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Request had no peer socket address (should never happen in normal operation).
    #[error("no peer address on request")]
    NoPeerAddr,
    /// Tailscale LocalAPI WhoIs call failed.
    #[error("WhoIs failed: {0}")]
    WhoIsFailed(String),
    /// Caller's identity does not match any authorized role for this mailbox.
    #[error("caller is not authorized")]
    Unauthorized,
    /// `senderUserId` in `Peer/deliver` body does not match the WhoIs-verified caller.
    #[error("senderUserId does not match caller identity")]
    SenderMismatch,
}

/// JMAP method-level error, serializable for inclusion in methodResponses.
/// See RFC 8620 §7.1 for standard error type strings.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("{error_type}")]
pub struct JmapError {
    /// Error type string per RFC 8620, e.g. "invalidArguments", "notFound".
    #[serde(rename = "type")]
    pub error_type: String,
    /// Optional human-readable description. Omitted from JSON when None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl JmapError {
    pub fn invalid_arguments(desc: impl Into<String>) -> Self {
        Self {
            error_type: "invalidArguments".into(),
            description: Some(desc.into()),
        }
    }

    pub fn forbidden_method() -> Self {
        Self {
            error_type: "forbidden".into(),
            description: None,
        }
    }

    pub fn not_found() -> Self {
        Self {
            error_type: "notFound".into(),
            description: None,
        }
    }

    /// RFC 8620 §5.1: the accountId does not correspond to a valid account.
    pub fn account_not_found() -> Self {
        Self {
            error_type: "accountNotFound".into(),
            description: None,
        }
    }

    pub fn server_fail(desc: impl Into<String>) -> Self {
        Self {
            error_type: "serverFail".into(),
            description: Some(desc.into()),
        }
    }

    pub fn cannot_calculate_changes() -> Self {
        Self {
            error_type: "cannotCalculateChanges".into(),
            description: None,
        }
    }

    pub fn state_mismatch() -> Self {
        Self {
            error_type: "stateMismatch".into(),
            description: None,
        }
    }

    pub fn unknown_capability(cap: impl Into<String>) -> Self {
        Self {
            error_type: "unknownCapability".into(),
            description: Some(cap.into()),
        }
    }

    pub fn request_too_large(desc: impl Into<String>) -> Self {
        Self {
            error_type: "requestTooLarge".into(),
            description: Some(desc.into()),
        }
    }

    pub fn unknown_method() -> Self {
        Self {
            error_type: "unknownMethod".into(),
            description: None,
        }
    }

    /// RFC 8620 §7.1: the request exceeds `maxObjectsInGet`, `maxObjectsInSet`,
    /// or some other per-method size limit.  Distinct from `requestTooLarge`
    /// (which is a request-level error); this is a method-level error returned
    /// inside `methodResponses` with HTTP 200.
    pub fn too_large() -> Self {
        Self {
            error_type: "tooLarge".into(),
            description: None,
        }
    }
}

/// Top-level error type for the kith system.
/// All crates convert their internal errors to KithError at boundaries.
#[derive(Debug, Error)]
pub enum KithError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Jmap(JmapError),
    #[error("storage error: {0}")]
    Store(String),
    #[error("validation error: {0}")]
    Validation(String),
}

impl From<JmapError> for KithError {
    fn from(e: JmapError) -> Self {
        KithError::Jmap(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent oracle: RFC 8620 §7.1 specifies these exact type strings.

    #[test]
    fn jmap_error_invalid_arguments_serializes_correctly() {
        let e = JmapError::invalid_arguments("ids field is required");
        let json_str = serde_json::to_string(&e).unwrap();
        // Must use "type" key (reserved word in Rust, handled by serde rename)
        assert!(json_str.contains("\"type\""));
        assert!(json_str.contains("\"invalidArguments\""));
        assert!(json_str.contains("\"description\""));
        assert!(json_str.contains("ids field is required"));
    }

    #[test]
    fn jmap_error_forbidden_method_omits_description() {
        let e = JmapError::forbidden_method();
        let json_str = serde_json::to_string(&e).unwrap();
        assert!(json_str.contains("\"forbidden\""));
        assert!(
            !json_str.contains("\"description\""),
            "None description must be omitted from JSON"
        );
    }

    #[test]
    fn jmap_error_not_found() {
        let e = JmapError::not_found();
        let json_str = serde_json::to_string(&e).unwrap();
        assert!(json_str.contains("\"notFound\""));
    }

    #[test]
    fn jmap_error_account_not_found() {
        // Oracle: RFC 8620 §5.1 specifies the exact type string "accountNotFound".
        let e = JmapError::account_not_found();
        let json_str = serde_json::to_string(&e).unwrap();
        assert!(json_str.contains("\"accountNotFound\""));
        assert!(
            !json_str.contains("\"description\""),
            "None description must be omitted from JSON"
        );
    }

    #[test]
    fn jmap_error_server_fail() {
        let e = JmapError::server_fail("internal error");
        let json_str = serde_json::to_string(&e).unwrap();
        assert!(json_str.contains("\"serverFail\""));
        assert!(json_str.contains("internal error"));
    }

    #[test]
    fn kith_error_from_auth_error() {
        let auth_err = AuthError::Unauthorized;
        let kith_err: KithError = auth_err.into();
        match kith_err {
            KithError::Auth(AuthError::Unauthorized) => {}
            _ => panic!("expected KithError::Auth(Unauthorized)"),
        }
    }

    #[test]
    fn kith_error_from_jmap_error() {
        let jmap_err = JmapError::not_found();
        let kith_err: KithError = jmap_err.into();
        match kith_err {
            KithError::Jmap(e) => assert_eq!(e.error_type, "notFound"),
            _ => panic!("expected KithError::Jmap"),
        }
    }

    #[test]
    fn auth_error_display_non_empty() {
        // Each variant must have a non-empty Display string
        assert!(!AuthError::NoPeerAddr.to_string().is_empty());
        assert!(!AuthError::WhoIsFailed("test".into()).to_string().is_empty());
        assert!(!AuthError::Unauthorized.to_string().is_empty());
        assert!(!AuthError::SenderMismatch.to_string().is_empty());
    }
}
