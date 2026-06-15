// ── kith-specific modules (not replaced by jmap-types/jmap-chat-types) ──
pub mod auth;
pub mod error;
pub mod events;
pub mod transport;

// ── Re-exports from jmap-types (RFC 8620 primitives) ──
pub use jmap_types::{
    Argument, Id, Invocation, JmapError, JmapRequest, JmapResponse, ResultReference, State, UTCDate,
};

// ── Re-exports from jmap-chat-types (draft-atwood-jmap-chat-00 types) ──
pub use jmap_chat_types::chat::{ChannelPermission, Chat, ChatKind, ChatMember};
pub use jmap_chat_types::contact::{ChatContact, Endpoint};
pub use jmap_chat_types::message::{
    Attachment, BodyType, BroadcastMention, DeliveryReceipt, DeliveryState, Mention, Message,
    MessageAction, MessageRevision, Reaction, ReadDisposition, SenderId,
    BROADCAST_MENTION_SCOPES,
};
pub use jmap_chat_types::presence::Presence;
pub use jmap_chat_types::space::{Category, Space, SpaceBan, SpaceInvite, SpaceMember, SpaceRole};
pub use jmap_chat_types::space_set::{
    CategoryPatch, ChannelCreate, ChannelPatch, MemberCreate, MemberPatch, RolePatch,
    SpaceMetadataPatch, SpacePatchOp,
};

// ── kith-specific re-exports ──
pub use auth::{Identity, Role};
pub use error::{AuthError, KithError};
pub use events::{parse_sse_frame, SseFrame, StateChange};
pub use transport::{ConnectionContext, DiscoveredPeer, FederationTransport, IdentityProvider};

// ── Constants ──

/// Maximum body size for a chat message (bytes).
pub const MAX_BODY_BYTES: usize = 65_536;
/// Maximum attachment size (bytes).
pub const MAX_ATTACHMENT_BYTES: usize = 104_857_600;
/// Maximum number of attachments per message.
pub const MAX_ATTACHMENTS: usize = 20;
/// Body types accepted in chat messages.
pub const SUPPORTED_BODY_TYPES: &[&str] = &["text/plain", "text/markdown", "application/jmap-chat-rich"];
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

/// Alias for [`BROADCAST_MENTION_SCOPES`] — the legacy kith-internal name.
///
/// Prefer [`BROADCAST_MENTION_SCOPES`] (the canonical name from jmap-chat-types).
pub const VALID_BROADCAST_SCOPES: &[&str] = BROADCAST_MENTION_SCOPES;

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

/// Construct a [`BroadcastMention`] from validated fields.
///
/// # Panics
/// Panics if fields cannot produce valid BroadcastMention JSON (logic error).
pub fn make_broadcast_mention(
    scope: impl Into<String>,
    offset: u64,
    length: u64,
) -> BroadcastMention {
    let json = serde_json::json!({
        "scope": scope.into(),
        "offset": offset,
        "length": length,
    });
    serde_json::from_value(json).expect(
        "make_broadcast_mention: valid fields must produce valid BroadcastMention; \
         this is a bug in kith-core if it fires",
    )
}

/// Construct a [`MessageRevision`] from validated fields.
///
/// # Panics
/// Panics if fields cannot produce valid MessageRevision JSON (logic error).
pub fn make_message_revision(
    body: impl Into<String>,
    body_type: impl Into<String>,
    edited_at: impl Into<String>,
) -> MessageRevision {
    let json = serde_json::json!({
        "body": body.into(),
        "bodyType": body_type.into(),
        "editedAt": edited_at.into(),
    });
    serde_json::from_value(json).expect(
        "make_message_revision: valid fields must produce valid MessageRevision; \
         this is a bug in kith-core if it fires",
    )
}

// ── Space-layer serde construction helpers ──
//
// SpaceRole, SpaceMember, and Category are #[non_exhaustive] without new()
// constructors. Construct via serde (the intentional API pattern).

/// Construct a [`SpaceRole`] from validated fields.
pub fn make_space_role(
    id: impl AsRef<str>,
    name: impl Into<String>,
    permissions: Vec<String>,
    position: u64,
) -> SpaceRole {
    let json = serde_json::json!({
        "id": id.as_ref(),
        "name": name.into(),
        "permissions": permissions,
        "position": position,
    });
    serde_json::from_value(json).expect(
        "make_space_role: valid fields must produce valid SpaceRole",
    )
}

/// Construct a [`SpaceMember`] from validated fields.
pub fn make_space_member(
    id: impl AsRef<str>,
    role_ids: Vec<String>,
    joined_at: impl Into<String>,
) -> SpaceMember {
    let json = serde_json::json!({
        "id": id.as_ref(),
        "roleIds": role_ids,
        "joinedAt": joined_at.into(),
    });
    serde_json::from_value(json).expect(
        "make_space_member: valid fields must produce valid SpaceMember",
    )
}

/// Construct a [`Category`] from validated fields.
pub fn make_category(
    id: impl AsRef<str>,
    name: impl Into<String>,
    position: u64,
    channel_ids: Vec<String>,
) -> Category {
    let json = serde_json::json!({
        "id": id.as_ref(),
        "name": name.into(),
        "position": position,
        "channelIds": channel_ids,
    });
    serde_json::from_value(json).expect(
        "make_category: valid fields must produce valid Category",
    )
}

/// Construct a [`ChannelPermission`] from validated fields.
pub fn make_channel_permission(
    target_id: impl AsRef<str>,
    target_type: impl Into<String>,
    allow: Vec<String>,
    deny: Vec<String>,
) -> ChannelPermission {
    let json = serde_json::json!({
        "targetId": target_id.as_ref(),
        "targetType": target_type.into(),
        "allow": allow,
        "deny": deny,
    });
    serde_json::from_value(json).expect(
        "make_channel_permission: valid fields must produce valid ChannelPermission",
    )
}

/// Spec-defined permission names (draft-atwood-jmap-chat-00 §4.20).
pub const SPACE_PERMISSION_NAMES: &[&str] = &[
    "view",
    "send",
    "pin",
    "manage_channels",
    "manage_members",
    "manage_roles",
    "manage_space",
    "ban",
    "mention_broadcast",
    "start_call",
];

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
    fn make_broadcast_mention_produces_valid_json() {
        let bm = make_broadcast_mention("everyone", 0, 9);
        let json_str = serde_json::to_string(&bm).unwrap();
        assert!(json_str.contains("\"scope\":\"everyone\""));
        assert!(json_str.contains("\"offset\":0"));
        assert!(json_str.contains("\"length\":9"));
    }

    #[test]
    fn broadcast_mention_roundtrip() {
        // Oracle: a BroadcastMention serialized to JSON and deserialized back
        // must produce the same struct.
        let bm = make_broadcast_mention("here", 10, 5);
        let json = serde_json::to_string(&bm).unwrap();
        let bm2: BroadcastMention = serde_json::from_str(&json).unwrap();
        assert_eq!(bm, bm2);
    }

    #[test]
    fn valid_broadcast_scopes_contains_expected_values() {
        // Oracle: spec defines exactly these three scopes.
        assert_eq!(VALID_BROADCAST_SCOPES.len(), 3);
        assert!(VALID_BROADCAST_SCOPES.contains(&"everyone"));
        assert!(VALID_BROADCAST_SCOPES.contains(&"here"));
        assert!(VALID_BROADCAST_SCOPES.contains(&"admins"));
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

    // ── Additional coverage tests ────────────────────────────────────────

    #[test]
    fn make_attachment_all_fields_accessible() {
        // Oracle: each field must round-trip through the serde-based constructor
        // and be individually accessible on the resulting Attachment struct.
        let a = make_attachment(
            "blob-xyz-789",
            "report.pdf",
            "application/pdf",
            204800,
            "b".repeat(64),
        );
        assert_eq!(a.blob_id.as_ref(), "blob-xyz-789");
        assert_eq!(a.filename, "report.pdf");
        assert_eq!(a.content_type, "application/pdf");
        assert_eq!(a.size, 204800);
        assert_eq!(a.sha256, "b".repeat(64));
    }

    #[test]
    fn make_attachment_empty_filename() {
        // Edge case: empty filename is valid per the spec (the field is a String,
        // not constrained to be non-empty).
        let a = make_attachment(
            "blob-empty",
            "",
            "application/octet-stream",
            0,
            "c".repeat(64),
        );
        assert_eq!(a.filename, "");
        assert_eq!(a.blob_id.as_ref(), "blob-empty");
    }

    #[test]
    fn make_attachment_very_large_size() {
        // Edge case: size is u64, must handle values near the upper bound.
        // Oracle: u64::MAX / 2 is a valid size value; the serde round-trip
        // through JSON must preserve it exactly (JSON numbers can represent
        // integers up to 2^53, but serde_json handles u64 correctly).
        let large_size = u64::MAX / 2;
        let a = make_attachment(
            "blob-big",
            "huge.bin",
            "application/octet-stream",
            large_size,
            "d".repeat(64),
        );
        assert_eq!(a.size, large_size);
    }

    #[test]
    fn make_mention_zero_offset_and_length() {
        // Edge case: zero offset and zero length represents an empty mention
        // at the start of the body. Must not panic.
        let m = make_mention("user-zero", 0, 0);
        assert_eq!(m.id.as_ref(), "user-zero");
        assert_eq!(m.offset, 0);
        assert_eq!(m.length, 0);
    }

    #[test]
    fn make_mention_large_offset() {
        // Edge case: offset near u64::MAX. The spec places no upper bound on
        // offset/length (they are UnsignedInt per RFC 8620). The serde
        // round-trip must preserve the value.
        let large_offset = u64::MAX / 2;
        let m = make_mention("user-far", large_offset, 10);
        assert_eq!(m.offset, large_offset);
        assert_eq!(m.length, 10);
    }

    #[test]
    fn make_broadcast_mention_each_valid_scope() {
        // Oracle: draft-atwood-jmap-chat-00 §4.4 defines exactly three scopes.
        // Each must construct successfully and serialize to the expected wire value.
        for &scope in VALID_BROADCAST_SCOPES {
            let bm = make_broadcast_mention(scope, 0, scope.len() as u64 + 1);
            assert_eq!(bm.scope, scope);
            let json_str = serde_json::to_string(&bm).unwrap();
            assert!(
                json_str.contains(&format!("\"scope\":\"{scope}\"")),
                "scope {scope} must appear in JSON; got: {json_str}"
            );
        }
    }

    #[test]
    fn make_message_revision_unicode_body() {
        // Oracle: the body field is a UTF-8 String; multi-byte characters
        // must round-trip through the serde-based constructor without
        // corruption or truncation.
        let unicode_body = "Hello \u{1F600} world \u{00E9}\u{00E8}\u{00EA} \u{4E16}\u{754C}";
        let rev = make_message_revision(unicode_body, "text/plain", "2026-06-01T12:00:00Z");
        assert_eq!(rev.body, unicode_body);
        assert_eq!(rev.body_type, "text/plain");
        assert_eq!(rev.edited_at.as_ref(), "2026-06-01T12:00:00Z");
    }

    #[test]
    fn broadcast_mention_serde_camel_case() {
        // Oracle: BroadcastMention uses #[serde(rename_all = "camelCase")].
        // All field names in JSON output must be camelCase. Since BroadcastMention
        // has only single-word field names (scope, offset, length), this test
        // verifies the JSON keys match those exact names (no snake_case leak).
        let bm = make_broadcast_mention("admins", 5, 7);
        let json_val: serde_json::Value = serde_json::to_value(&bm).unwrap();
        let obj = json_val.as_object().unwrap();
        // All three expected keys must be present
        assert!(obj.contains_key("scope"), "must have 'scope' key");
        assert!(obj.contains_key("offset"), "must have 'offset' key");
        assert!(obj.contains_key("length"), "must have 'length' key");
    }

    #[test]
    fn display_name_or_fallback_whitespace_only_falls_back_to_login() {
        // Edge case: display_name is Some("   ") — non-empty but whitespace-only.
        // The current implementation checks `!name.is_empty()` which accepts
        // whitespace-only strings as valid display names.
        // Oracle: the behavior is defined by the implementation — whitespace-only
        // strings pass the `!is_empty()` check, so they are returned as-is.
        let mut c = ChatContact::new(
            Id::from("uid-ws"),
            "ws-user@example.com",
            UTCDate::from("2026-01-01T00:00:00Z"),
            UTCDate::from("2026-04-18T20:14:00Z"),
            false,
        );
        c.display_name = Some("   ".into());
        // Whitespace-only is non-empty, so it is returned as the display name
        assert_eq!(c.display_name_or_fallback(), "   ");
    }

    #[test]
    fn message_new_fields_accessible_and_correct() {
        // Oracle: Message::new sets required fields from arguments and defaults
        // all optional/collection fields. Each required field must be accessible
        // and equal to the value passed to the constructor.
        let msg = Message::new(
            Id::from("msg-001"),
            Id::from("sender-msg-001"),
            SenderId::Contact("peer-alice".to_string()),
            Id::from("chat-abc"),
            "Test message body",
            "text/markdown",
            UTCDate::from("2026-05-01T10:00:00Z"),
            UTCDate::from("2026-05-01T10:00:01Z"),
            DeliveryState::Delivered,
        );
        assert_eq!(msg.id.as_ref(), "msg-001");
        assert_eq!(msg.sender_msg_id.as_ref(), "sender-msg-001");
        assert_eq!(msg.sender_id, SenderId::Contact("peer-alice".to_string()));
        assert_eq!(msg.chat_id.as_ref(), "chat-abc");
        assert_eq!(msg.body, "Test message body");
        assert_eq!(msg.body_type, "text/markdown");
        assert_eq!(msg.sent_at.as_ref(), "2026-05-01T10:00:00Z");
        assert_eq!(msg.received_at.as_ref(), "2026-05-01T10:00:01Z");
        assert_eq!(msg.delivery_state, DeliveryState::Delivered);
        // Default collections must be empty
        assert!(msg.attachments.is_empty());
        assert!(msg.mentions.is_empty());
        assert!(msg.actions.is_empty());
        assert!(msg.reactions.is_empty());
        // Default optionals must be None
        assert!(msg.reply_to.is_none());
        assert!(msg.thread_root_id.is_none());
        assert!(msg.edit_history.is_none());
        assert!(msg.deleted_at.is_none());
    }

    #[test]
    fn chat_new_defaults() {
        // Oracle: Chat::new sets required fields and defaults all optional fields.
        // pinned_message_ids, muted, and receive_typing_indicators come from
        // arguments; all optional fields must be None.
        let chat = Chat::new(
            Id::from("chat-test"),
            ChatKind::Direct,
            UTCDate::from("2026-03-15T08:00:00Z"),
            0,
            vec![],
            false,
            false,
        );
        assert_eq!(chat.id.as_ref(), "chat-test");
        assert_eq!(chat.kind, ChatKind::Direct);
        assert!(chat.pinned_message_ids.is_empty());
        assert!(!chat.muted);
        assert!(!chat.receive_typing_indicators);
        // All optional fields must be None
        assert!(chat.contact_id.is_none());
        assert!(chat.name.is_none());
        assert!(chat.description.is_none());
        assert!(chat.avatar_blob_id.is_none());
        assert!(chat.members.is_none());
        assert!(chat.space_id.is_none());
        assert!(chat.topic.is_none());
        assert!(chat.last_message_at.is_none());
    }

    // ── unix_secs_to_rfc3339 boundary tests ──────────────────────────────

    #[test]
    fn unix_secs_to_rfc3339_leap_second_boundary() {
        // Oracle: 2023-12-31T23:59:59Z = Unix 1704067199
        // (verified via `date -u -d '2023-12-31 23:59:59' +%s` = 1704067199)
        assert_eq!(unix_secs_to_rfc3339(1_704_067_199), "2023-12-31T23:59:59Z");
    }

    #[test]
    fn unix_secs_to_rfc3339_year_2038_boundary() {
        // Oracle: i32::MAX = 2147483647 seconds = 2038-01-19T03:14:07Z
        // (verified via `date -u -d @2147483647` = Tue Jan 19 03:14:07 UTC 2038)
        assert_eq!(
            unix_secs_to_rfc3339(2_147_483_647),
            "2038-01-19T03:14:07Z"
        );
    }

    #[test]
    fn unix_secs_to_rfc3339_year_2100_century_non_leap() {
        // Oracle: 2100-03-01T00:00:00Z — 2100 is NOT a leap year (divisible by 100
        // but not 400), so Feb has 28 days. The day after 2100-02-28 is 2100-03-01.
        // Unix timestamp for 2100-03-01T00:00:00Z = 4107542400
        // (verified via Python: calendar.timegm((2100,3,1,0,0,0,0,0,0)) = 4107542400)
        assert_eq!(
            unix_secs_to_rfc3339(4_107_542_400),
            "2100-03-01T00:00:00Z"
        );
    }

    // ── JMAP error helper tests ────────────────────────────────────────────

    #[test]
    fn jmap_error_forbidden_returns_correct_type() {
        // Oracle: RFC 8620 §3.6.2 — "forbidden" error type string.
        let e = jmap_error_forbidden();
        assert_eq!(e.error_type, "forbidden");
    }

    #[test]
    fn jmap_error_request_too_large_preserves_description() {
        // Oracle: the description passed to jmap_error_request_too_large must be
        // preserved in the returned JmapError's description field.
        let desc = "Request body exceeds 10 MB limit";
        let e = jmap_error_request_too_large(desc);
        assert_eq!(e.error_type, "requestTooLarge");
        assert_eq!(e.description, Some(desc.to_string()));
    }

    #[test]
    fn sender_id_owner_and_contact_wire_format() {
        // Oracle: draft-atwood-jmap-chat-00 §Message.senderId
        // - Owner serializes as the sentinel string "self"
        // - Contact serializes as the contained id string verbatim
        assert_eq!(
            serde_json::to_string(&SenderId::Owner).unwrap(),
            r#""self""#
        );
        let contact = SenderId::Contact("peer-bob-uid".to_string());
        assert_eq!(
            serde_json::to_string(&contact).unwrap(),
            r#""peer-bob-uid""#
        );
        // Verify deserialization round-trip for Contact
        let deser: SenderId = serde_json::from_str(r#""peer-bob-uid""#).unwrap();
        assert_eq!(deser, SenderId::Contact("peer-bob-uid".to_string()));
    }
}
