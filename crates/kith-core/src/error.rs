use thiserror::Error;

/// Authentication and authorization errors.
#[derive(Debug, Error)]
#[non_exhaustive]
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

/// Top-level error type for the kith system.
/// All crates convert their internal errors to KithError at boundaries.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KithError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Jmap(jmap_types::JmapError),
    #[error("storage error: {0}")]
    Store(String),
    #[error("validation error: {0}")]
    Validation(String),
}

impl From<jmap_types::JmapError> for KithError {
    fn from(e: jmap_types::JmapError) -> Self {
        KithError::Jmap(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmap_types::JmapError;

    #[test]
    fn jmap_error_invalid_arguments_serializes_correctly() {
        let e = JmapError::invalid_arguments("ids field is required");
        let json_str = serde_json::to_string(&e).unwrap();
        assert!(json_str.contains("\"type\""));
        assert!(json_str.contains("\"invalidArguments\""));
        assert!(json_str.contains("\"description\""));
        assert!(json_str.contains("ids field is required"));
    }

    #[test]
    fn jmap_error_forbidden_omits_description() {
        let e = JmapError::forbidden();
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
        assert!(!AuthError::NoPeerAddr.to_string().is_empty());
        assert!(!AuthError::WhoIsFailed("test".into()).to_string().is_empty());
        assert!(!AuthError::Unauthorized.to_string().is_empty());
        assert!(!AuthError::SenderMismatch.to_string().is_empty());
    }
}
