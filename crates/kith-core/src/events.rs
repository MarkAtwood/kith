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
