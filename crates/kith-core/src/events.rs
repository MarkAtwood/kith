use serde::{Deserialize, Serialize};

/// A state-change notification emitted by the store layer when any JMAP
/// object type advances its state counter.
///
/// Consumers subscribe via `kith_events::make_channel` and receive one
/// `StateChange` for every object type that was modified.  The receiver
/// calls `<Type>/changes` to pull the delta — the event only signals
/// *that* a change occurred, not *what* changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateChange {
    /// JMAP object type name, e.g. "ChatContact", "Chat", "Message".
    pub type_name: String,
    /// New opaque state token, e.g. "s-42".
    pub new_state: String,
}

/// A parsed SSE event block (lines between `\n\n` separators).
///
/// Contains raw field values extracted per the
/// [Server-Sent Events spec](https://html.spec.whatwg.org/multipage/server-sent-events.html):
/// - `event:` → `event_type`
/// - `data:` (all lines joined with `\n`) → `data`
/// - `id:` → `id`
///
/// This struct is the single shared representation used by both `kithctl` and
/// `kith-tui`. Any change to the kithd SSE wire format must be reflected here.
#[derive(Debug, Default, PartialEq)]
pub struct SseFrame {
    /// Value of the `event:` field, if present.
    pub event_type: Option<String>,
    /// All `data:` lines joined with `\n`. `None` if there were no `data:` lines.
    pub data: Option<String>,
    /// Value of the `id:` field, if present.
    pub id: Option<String>,
}

/// Parse a single SSE event block (lines between `\n\n` separators).
///
/// This is the shared low-level field extractor. `kithctl` and `kith-tui`
/// both delegate to this function so changes to the wire format are made
/// in one place only.
pub fn parse_sse_frame(block: &str) -> SseFrame {
    let mut frame = SseFrame::default();
    let mut data_parts: Vec<&str> = Vec::new();

    for line in block.lines() {
        if let Some(value) = line.strip_prefix("event:") {
            frame.event_type = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            data_parts.push(value.trim());
        } else if let Some(value) = line.strip_prefix("id:") {
            frame.id = Some(value.trim().to_owned());
        }
        // Comments (lines starting with ':') and unknown fields are silently ignored.
    }

    if !data_parts.is_empty() {
        frame.data = Some(data_parts.join("\n"));
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── StateChange tests ──────────────────────────────────────────────────

    // Test: StateChange serialization round-trip.
    // Oracle: serde Serialize + Deserialize derive on StateChange must produce
    // an identical struct after JSON round-trip.
    #[test]
    fn state_change_serialization_round_trip() {
        let original = StateChange {
            type_name: "ChatContact".to_string(),
            new_state: "s-42".to_string(),
        };
        let json_str = serde_json::to_string(&original).unwrap();
        let deserialized: StateChange = serde_json::from_str(&json_str).unwrap();
        assert_eq!(original, deserialized);
    }

    // Test: StateChange type_name and new_state fields are correct in JSON.
    // Oracle: the struct uses #[derive(Serialize, Deserialize)] with default
    // field names (snake_case). Verify the JSON keys and values match.
    #[test]
    fn state_change_fields_correct_in_json() {
        let sc = StateChange {
            type_name: "Message".to_string(),
            new_state: "s-99".to_string(),
        };
        let json_val: serde_json::Value = serde_json::to_value(&sc).unwrap();
        assert_eq!(json_val["type_name"], "Message");
        assert_eq!(json_val["new_state"], "s-99");
    }

    // ── parse_sse_frame tests ──────────────────────────────────────────────

    // Test: parse_sse_frame with event+data+id — all fields populated.
    // Oracle: SSE spec (WHATWG HTML Living Standard §9.2) — event, data, id
    // are the three primary field types.
    #[test]
    fn parse_sse_frame_with_event_data_id() {
        let block = "event: stateChange\ndata: {\"type\":\"Message\"}\nid: 42\n";
        let frame = parse_sse_frame(block);
        assert_eq!(frame.event_type, Some("stateChange".to_string()));
        assert_eq!(frame.data, Some("{\"type\":\"Message\"}".to_string()));
        assert_eq!(frame.id, Some("42".to_string()));
    }

    // Test: parse_sse_frame with data only (no event type).
    // Oracle: SSE spec — the event type defaults to "message" in the browser API
    // when not specified, but parse_sse_frame just returns None for event_type.
    #[test]
    fn parse_sse_frame_data_only() {
        let block = "data: hello world\n";
        let frame = parse_sse_frame(block);
        assert_eq!(frame.event_type, None);
        assert_eq!(frame.data, Some("hello world".to_string()));
        assert_eq!(frame.id, None);
    }

    // Test: parse_sse_frame with multiple data lines joined with newline.
    // Oracle: SSE spec §9.2.4 — "If the field name is data, append the field
    // value to the data buffer, then append a single U+000A LINE FEED."
    // Our implementation joins with \n.
    #[test]
    fn parse_sse_frame_multiple_data_lines() {
        let block = "data: line one\ndata: line two\ndata: line three\n";
        let frame = parse_sse_frame(block);
        assert_eq!(frame.data, Some("line one\nline two\nline three".to_string()));
    }

    // Test: parse_sse_frame with comment lines (ignored).
    // Oracle: SSE spec §9.2.4 — lines starting with ':' are comments and
    // must be silently ignored.
    #[test]
    fn parse_sse_frame_comment_lines_ignored() {
        let block = ": this is a comment\nevent: ping\n: another comment\ndata: pong\n";
        let frame = parse_sse_frame(block);
        assert_eq!(frame.event_type, Some("ping".to_string()));
        assert_eq!(frame.data, Some("pong".to_string()));
    }

    // Test: parse_sse_frame with empty block returns default SseFrame.
    // Oracle: SSE spec — an empty block (between two \n\n separators) means
    // no fields were set. All fields remain at their default (None).
    #[test]
    fn parse_sse_frame_empty_block_returns_default() {
        let frame = parse_sse_frame("");
        assert_eq!(frame, SseFrame::default());
        assert_eq!(frame.event_type, None);
        assert_eq!(frame.data, None);
        assert_eq!(frame.id, None);
    }

    // Test: parse_sse_frame with unknown fields (ignored).
    // Oracle: SSE spec §9.2.4 — "If the line is not empty but does not
    // contain a U+003A COLON character (:) ... or if the field name is not
    // one of event/data/id/retry, the line is ignored."
    #[test]
    fn parse_sse_frame_unknown_fields_ignored() {
        let block = "event: state\nretry: 3000\nfoo: bar\ndata: payload\n";
        let frame = parse_sse_frame(block);
        assert_eq!(frame.event_type, Some("state".to_string()));
        assert_eq!(frame.data, Some("payload".to_string()));
        // retry and foo are not captured by SseFrame
        assert_eq!(frame.id, None);
    }
}
