// ── kith-specific modules (not replaced by jmap-types/jmap-chat-types) ──
pub mod auth;
pub mod error;
pub mod events;

// ── Re-exports from jmap-types (RFC 8620 primitives) ──
pub use jmap_types::{
    Argument, Id, Invocation, JmapError, JmapRequest, JmapResponse, ResultReference, State, UTCDate,
};

// ── Re-exports from jmap-chat-types (draft-atwood-jmap-chat-00 types) ──
pub use jmap_chat_types::chat::{ChannelPermission, Chat, ChatKind, ChatMember};
pub use jmap_chat_types::contact::{ChatContact, Endpoint};
pub use jmap_chat_types::message::{
    Attachment, BodyType, DeliveryReceipt, DeliveryState, Mention, Message, MessageAction,
    MessageRevision, Reaction, ReadDisposition, SenderId,
};

// ── kith-specific re-exports ──
pub use auth::{Identity, Role};
pub use error::{AuthError, KithError};
pub use events::{parse_sse_frame, SseFrame, StateChange};

// ── Constants ──

/// Maximum body size for a chat message (bytes).
pub const MAX_BODY_BYTES: usize = 65_536;
/// Maximum attachment size (bytes).
pub const MAX_ATTACHMENT_BYTES: usize = 104_857_600;
/// Maximum JMAP API request body size (bytes).
///
/// Advertised in the Session object as `maxSizeRequest` (RFC 8620 §2).
/// The kithd HTTP layer enforces this via `DefaultBodyLimit`.
pub const MAX_REQUEST_BYTES: usize = 10_485_760;
/// Maximum number of object IDs in a single /get call (RFC 8620 §5.1).
///
/// Advertised in the Session object as `maxObjectsInGet`.
/// /get handlers MUST return `tooLarge` when the `ids` array exceeds this.
pub const MAX_OBJECTS_IN_GET: usize = 500;

// ── Constructor helpers for #[non_exhaustive] types ──
//
// jmap-chat-types marks Attachment, Mention, etc. as #[non_exhaustive]
// without providing new() constructors. We construct them via serde
// deserialization from known-valid JSON. The expect() messages are
// intentionally detailed for defensive debugging.

/// Construct an [`Attachment`] from validated fields.
///
/// # Panics
/// Panics (via expect) if the fields cannot produce a valid Attachment JSON.
/// This is a logic error — all field types are correct by construction.
pub fn make_attachment(
    blob_id: impl AsRef<str>,
    filename: impl Into<String>,
    content_type: impl Into<String>,
    size: u64,
    sha256: impl Into<String>,
) -> Attachment {
    let json = serde_json::json!({
        "blobId": blob_id.as_ref(),
        "filename": filename.into(),
        "contentType": content_type.into(),
        "size": size,
        "sha256": sha256.into(),
    });
    serde_json::from_value(json).expect(
        "make_attachment: valid fields must produce valid Attachment; \
         this is a bug in kith-core if it fires",
    )
}

/// Construct a [`Mention`] from validated fields.
///
/// # Panics
/// Panics if fields cannot produce valid Mention JSON (logic error).
pub fn make_mention(id: impl AsRef<str>, offset: u64, length: u64) -> Mention {
    let json = serde_json::json!({
        "id": id.as_ref(),
        "offset": offset,
        "length": length,
    });
    serde_json::from_value(json).expect(
        "make_mention: valid fields must produce valid Mention; \
         this is a bug in kith-core if it fires",
    )
}

// ── Extension traits for kith-specific methods ──

/// Extension methods for [`ChatContact`] that are kith-specific
/// (not part of the jmap-chat-types crate).
pub trait ChatContactExt {
    /// Returns the best available display string for this contact.
    /// Falls back: display_name → login → id. Never returns an empty string.
    fn display_name_or_fallback(&self) -> &str;
}

impl ChatContactExt for ChatContact {
    fn display_name_or_fallback(&self) -> &str {
        if let Some(ref name) = self.display_name {
            if !name.is_empty() {
                return name.as_str();
            }
        }
        let login: &str = self.login.as_ref();
        if !login.is_empty() {
            return login;
        }
        self.id.as_ref()
    }
}

// ── JmapError compatibility shims ──
//
// kith code used factory methods that don't exist on jmap_types::JmapError
// with the same signatures. These free functions bridge the gap.

/// Create a "forbidden" JmapError.
/// Shim: kith called this `forbidden_method()`, jmap-types calls it `forbidden()`.
pub fn jmap_error_forbidden() -> JmapError {
    JmapError::forbidden()
}

/// Create an "unknownCapability" JmapError with the failing URI.
/// Shim: kith called this `unknown_capability(cap)`, jmap-types calls it
/// `unknown_capability_with_detail(uri)`.
pub fn jmap_error_unknown_capability(cap: impl Into<String>) -> JmapError {
    JmapError::unknown_capability_with_detail(cap)
}

/// Create a "requestTooLarge" JmapError with a description.
/// Shim: kith's version took a description; jmap-types' does not.
/// We use `custom()` to preserve the description.
pub fn jmap_error_request_too_large(desc: impl Into<String>) -> JmapError {
    let mut e = JmapError::request_too_large();
    e.description = Some(desc.into());
    e
}

// ── Utility functions ──

/// Returns `true` if `ip` is in the address space reserved for Tailscale peers:
/// - IPv4 `100.64.0.0/10` (CGNAT range used by Tailscale)
/// - IPv6 `fc00::/7` (ULA; Tailscale uses `fd7a:115c:a1e0::/48` within this)
///
/// All other addresses — loopback, unspecified, RFC 1918 private, link-local,
/// and public internet — return `false`.
pub fn is_tailnet_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (64..=127).contains(&o[1])
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
            (segs[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Format a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC) as an
/// RFC 3339 UTC string (e.g., `"2020-09-13T12:26:40Z"`).
///
/// Returns a plain `String` (not `UTCDate`) because the caller often needs
/// to pass it to both `UTCDate::from()` and string contexts. Callers that
/// need a `UTCDate` should wrap: `UTCDate::from(unix_secs_to_rfc3339(t))`.
///
/// Uses the Hinnant civil-calendar algorithm for accuracy without an
/// external time crate.  Correct for dates from the Unix epoch (t=0) through 2299.
///
/// # Panics (debug builds only)
/// Panics if `secs` exceeds `i64::MAX` as days, because the Hinnant algorithm
/// requires `days` to fit in an `i64`.
pub fn unix_secs_to_rfc3339(secs: u64) -> String {
    let secs_in_day: u64 = 86400;
    let days = secs / secs_in_day;
    let time_secs = secs % secs_in_day;

    let hh = time_secs / 3600;
    let mm = (time_secs % 3600) / 60;
    let ss = time_secs % 60;

    debug_assert!(
        days <= i64::MAX as u64,
        "unix_secs_to_rfc3339: secs={secs} overflows i64 day count"
    );
    let days = days as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn is_tailnet_ip_accepts_cgnat() {
        assert!(is_tailnet_ip("100.64.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_tailnet_ip("100.100.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_tailnet_ip("100.127.255.254".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn is_tailnet_ip_rejects_outside_cgnat() {
        assert!(!is_tailnet_ip("100.63.255.255".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("100.128.0.0".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("169.254.1.1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn is_tailnet_ip_accepts_ula_ipv6() {
        assert!(is_tailnet_ip(
            "fd7a:115c:a1e0::1".parse::<IpAddr>().unwrap()
        ));
        assert!(is_tailnet_ip("fd00::1".parse::<IpAddr>().unwrap()));
        assert!(is_tailnet_ip("fc00::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn is_tailnet_ip_rejects_non_ula_ipv6() {
        assert!(!is_tailnet_ip("fe80::1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("::1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("2001:db8::1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("2600::1".parse::<IpAddr>().unwrap()));
        assert!(!is_tailnet_ip("::".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn unix_secs_to_rfc3339_known_values() {
        assert_eq!(unix_secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_secs_to_rfc3339(86400), "1970-01-02T00:00:00Z");
        assert_eq!(unix_secs_to_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(unix_secs_to_rfc3339(1776515696), "2026-04-18T12:34:56Z");
        assert_eq!(unix_secs_to_rfc3339(951782400), "2000-02-29T00:00:00Z");
        assert_eq!(unix_secs_to_rfc3339(1704067199), "2023-12-31T23:59:59Z");
    }

    // Verify jmap-chat-types wire format matches what kith expects.
    // These are regression guards — if jmap-chat-types changes its serde
    // behavior, these tests catch it before it reaches production.

    #[test]
    fn delivery_state_wire_format_matches_spec() {
        // Oracle: draft-atwood-jmap-chat-00 §Message.deliveryState
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
    fn message_wire_format_field_names() {
        // Oracle: draft-atwood-jmap-chat-00 §Message — field names are camelCase
        let msg = Message::new(
            Id::from("01JVWXYZ0000000000000000AB"),
            Id::from("01JVWXYZ0000000000000000AB"),
            SenderId::Owner,
            Id::from("chat-001"),
            "Hello, world!",
            "text/plain",
            UTCDate::from("2026-04-18T20:00:00Z"),
            UTCDate::from("2026-04-18T20:00:01Z"),
            DeliveryState::Received,
        );
        let json_str = serde_json::to_string(&msg).unwrap();
        assert!(json_str.contains("\"chatId\""), "must use camelCase chatId");
        assert!(
            json_str.contains("\"senderId\""),
            "must use camelCase senderId"
        );
        assert!(
            json_str.contains("\"senderMsgId\""),
            "must use camelCase senderMsgId"
        );
        assert!(
            json_str.contains("\"bodyType\""),
            "must use camelCase bodyType"
        );
        assert!(json_str.contains("\"sentAt\""), "must use camelCase sentAt");
        assert!(
            json_str.contains("\"receivedAt\""),
            "must use camelCase receivedAt"
        );
        assert!(
            json_str.contains("\"deliveryState\""),
            "must use camelCase deliveryState"
        );
    }

    #[test]
    fn sender_id_self_wire_format() {
        // Oracle: draft-atwood-jmap-chat-00 §Message.senderId — "self" for owner
        let json_str = serde_json::to_string(&SenderId::Owner).unwrap();
        assert_eq!(json_str, r#""self""#);
    }

    #[test]
    fn chat_kind_wire_format() {
        // Oracle: draft-atwood-jmap-chat-00 §Chat.kind
        assert_eq!(
            serde_json::to_string(&ChatKind::Direct).unwrap(),
            r#""direct""#
        );
        assert_eq!(
            serde_json::to_string(&ChatKind::Group).unwrap(),
            r#""group""#
        );
        assert_eq!(
            serde_json::to_string(&ChatKind::Channel).unwrap(),
            r#""channel""#
        );
    }

    #[test]
    fn chat_contact_wire_format_field_names() {
        // Oracle: draft-atwood-jmap-chat-00 §ChatContact — camelCase
        let contact = ChatContact::new(
            Id::from("uid-456"),
            "bob@example.com",
            UTCDate::from("2026-01-01T00:00:00Z"),
            UTCDate::from("2026-04-18T20:14:00Z"),
            false,
        );
        let json_str = serde_json::to_string(&contact).unwrap();
        assert!(json_str.contains("\"firstSeenAt\""));
        assert!(json_str.contains("\"lastSeenAt\""));
        assert!(!json_str.contains("\"first_seen_at\""));
    }

    #[test]
    fn make_attachment_produces_valid_json() {
        let a = make_attachment("blob-abc", "photo.png", "image/png", 102400, "a".repeat(64));
        let json_str = serde_json::to_string(&a).unwrap();
        assert!(json_str.contains("\"blobId\""));
        assert!(json_str.contains("\"contentType\""));
        assert!(json_str.contains("\"blob-abc\""));
    }

    #[test]
    fn make_mention_produces_valid_json() {
        let m = make_mention("user-alice", 6, 6);
        let json_str = serde_json::to_string(&m).unwrap();
        assert!(json_str.contains("\"user-alice\""));
        assert!(json_str.contains("\"offset\":6"));
        assert!(json_str.contains("\"length\":6"));
    }

    #[test]
    fn display_name_or_fallback_uses_display_name() {
        let mut c = ChatContact::new(
            Id::from("uid-456"),
            "bob@example.com",
            UTCDate::from("2026-01-01T00:00:00Z"),
            UTCDate::from("2026-04-18T20:14:00Z"),
            false,
        );
        c.display_name = Some("Bob Smith".into());
        assert_eq!(c.display_name_or_fallback(), "Bob Smith");
    }

    #[test]
    fn display_name_or_fallback_uses_login() {
        let c = ChatContact::new(
            Id::from("uid-456"),
            "bob@example.com",
            UTCDate::from("2026-01-01T00:00:00Z"),
            UTCDate::from("2026-04-18T20:14:00Z"),
            false,
        );
        assert_eq!(c.display_name_or_fallback(), "bob@example.com");
    }

    #[test]
    fn display_name_or_fallback_uses_id() {
        let c = ChatContact::new(
            Id::from("uid-456"),
            "",
            UTCDate::from("2026-01-01T00:00:00Z"),
            UTCDate::from("2026-04-18T20:14:00Z"),
            false,
        );
        assert_eq!(c.display_name_or_fallback(), "uid-456");
    }

    #[test]
    fn display_name_or_fallback_ignores_empty_display_name() {
        let mut c = ChatContact::new(
            Id::from("uid-456"),
            "bob@example.com",
            UTCDate::from("2026-01-01T00:00:00Z"),
            UTCDate::from("2026-04-18T20:14:00Z"),
            false,
        );
        c.display_name = Some(String::new());
        assert_eq!(c.display_name_or_fallback(), "bob@example.com");
    }

    #[test]
    fn id_newtype_compatible_with_string_ops() {
        // Verify Id newtype supports the operations kith needs
        let id = Id::from("test-123");
        assert_eq!(id.as_ref(), "test-123");
        assert!(id == "test-123");
        let s: String = id.into_inner();
        assert_eq!(s, "test-123");
    }

    #[test]
    fn utcdate_newtype_compatible_with_string_ops() {
        let d = UTCDate::from("2026-01-01T00:00:00Z");
        assert_eq!(d.as_ref(), "2026-01-01T00:00:00Z");
        let s: String = d.into_inner();
        assert_eq!(s, "2026-01-01T00:00:00Z");
    }
}
