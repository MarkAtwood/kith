use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

/// Which panel currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    ChatList,
    Input,
}

/// Current connection state to the local kithd instance.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Reconnecting,
    Error(String),
}

impl fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionStatus::Connecting => write!(f, "Connecting"),
            ConnectionStatus::Connected => write!(f, "Connected"),
            ConnectionStatus::Reconnecting => {
                write!(f, "Reconnecting (will retry automatically)")
            }
            ConnectionStatus::Error(msg) => write!(f, "Error: {msg}"),
        }
    }
}

/// All mutable runtime state for the TUI.
pub struct AppState {
    /// Set to true to exit the event loop.
    pub quit: bool,
    /// Terminal size in cells (width, height).
    pub terminal_size: (u16, u16),
    /// Which panel has keyboard focus.
    pub focus: Focus,
    /// Chat names shown in the left panel (placeholder).
    pub chat_list: Vec<String>,
    /// JMAP chat IDs, parallel to chat_list.
    pub chat_ids: Vec<String>,
    /// Index into chat_list of the currently selected chat.
    pub selected_chat: usize,
    /// Message display lines. Parallel to `message_ids` and `message_senders` —
    /// all three must always have the same length. Push/pop to all three together.
    pub messages: VecDeque<String>,
    /// Lines-from-bottom scroll offset (0 = show latest).
    pub scroll_offset: usize,
    /// Current text input buffer.
    pub input: String,
    /// Byte offset of the insertion cursor; always a UTF-8 char boundary.
    pub input_cursor: usize,
    /// Maps contact_id -> display_name.
    pub contacts: HashMap<String, String>,
    /// Current connection state to kithd.
    pub connection_status: ConnectionStatus,
    /// Latest Message state token from the server (empty = "s-0").
    pub message_state: String,
    /// Flag set by handle_key(Enter); cleared by run() after attempting send.
    pub should_send_message: bool,
    /// Error text + timestamp for 3-second status bar notification. None = no error.
    pub error_notification: Option<(String, std::time::Instant)>,
    /// JMAP message IDs. Parallel to `messages` — see invariant note there.
    pub message_ids: VecDeque<String>,
    /// senderId for each message ("self" for outbound). Parallel to `messages` — see invariant note there.
    pub message_senders: VecDeque<String>,
    /// JMAP IDs of inbound messages (senderId != "self") not yet acknowledged
    /// with readAt. Cleared after successful send_read_receipts call.
    pub unread_message_ids: HashSet<String>,
}

impl AppState {
    /// Construct initial state with empty data.
    ///
    /// Invariant: `messages`, `message_ids`, and `message_senders` are always
    /// the same length.  All three start empty so the invariant holds from
    /// construction.
    pub fn new() -> Self {
        AppState {
            quit: false,
            terminal_size: (80, 24),
            focus: Focus::Input,
            chat_list: vec![],
            chat_ids: vec![],
            selected_chat: 0,
            messages: VecDeque::new(),
            scroll_offset: 0,
            input: String::new(),
            input_cursor: 0,
            contacts: HashMap::new(),
            connection_status: ConnectionStatus::Connecting,
            message_state: String::new(),
            should_send_message: false,
            error_notification: None,
            message_ids: VecDeque::new(),
            message_senders: VecDeque::new(),
            unread_message_ids: HashSet::new(),
        }
    }

    /// Clamp scroll_offset so it cannot exceed messages.len() - visible_height.
    /// visible_height is the number of message lines that fit in the panel.
    pub fn clamp_scroll(&mut self, visible_height: usize) {
        let max = self.messages.len().saturating_sub(visible_height);
        if self.scroll_offset > max {
            self.scroll_offset = max;
        }
    }

    /// Set an error notification that will be shown in the status bar for 3 seconds.
    /// The message must already be ANSI-sanitized before calling this.
    pub fn set_error(&mut self, msg: &str) {
        self.error_notification = Some((msg.to_string(), std::time::Instant::now()));
    }

    /// Clear error_notification if it has been showing for more than 3 seconds.
    pub fn clear_stale_error(&mut self) {
        if let Some((_, ts)) = &self.error_notification {
            if ts.elapsed() > std::time::Duration::from_secs(3) {
                self.error_notification = None;
            }
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Strip all ANSI/VT100 escape sequences from `s` and return only the
/// visible characters.
///
/// Sequences stripped:
/// - CSI sequences: `ESC [` followed by parameter bytes (0x30–0x3F),
///   intermediate bytes (0x20–0x2F), and a final byte (0x40–0x7E).
///   This covers SGR color/style (`ESC[...m`), cursor movement
///   (`ESC[A`/`ESC[B`/`ESC[H`/…), screen clear (`ESC[2J`), and all
///   other CSI sequences.
/// - OSC sequences: `ESC ]` followed by any bytes up to a BEL (0x07)
///   or a String Terminator (`ESC \`).
/// - Any remaining bare ESC byte not consumed by the above.
///
/// The function is pure: no I/O, no side effects.
pub fn sanitize_display(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != 0x1b {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // ESC byte found. Peek at the next byte to classify the sequence.
        if i + 1 >= bytes.len() {
            // Lone ESC at end of input: discard it.
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            b'[' => {
                // CSI sequence: ESC [ {param bytes}* {intermediate bytes}* {final byte}
                // Parameter bytes: 0x30–0x3F  (digits, ';', ':', '<', '=', '>', '?')
                // Intermediate bytes: 0x20–0x2F (space, '!', '"', …, '/')
                // Final byte: 0x40–0x7E ('@' through '~', includes 'm', 'A', 'B', 'J', …)
                i += 2; // consume ESC [
                while i < bytes.len() {
                    let b = bytes[i];
                    i += 1;
                    if (0x40..=0x7e).contains(&b) {
                        // Final byte consumed — sequence complete.
                        break;
                    }
                    // Parameter or intermediate byte — keep consuming.
                }
            }
            b']' => {
                // OSC sequence: ESC ] ... BEL  or  ESC ] ... ESC \
                i += 2; // consume ESC ]
                while i < bytes.len() {
                    if bytes[i] == 0x07 {
                        // BEL terminates the OSC.
                        i += 1;
                        break;
                    }
                    if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                        // ST (String Terminator = ESC \) terminates the OSC.
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            _ => {
                // Unknown two-byte escape: discard only the ESC byte. The next
                // byte will be re-evaluated on the next iteration.
                i += 1;
            }
        }
    }
    // out contains only bytes that were never part of an escape sequence;
    // the source was valid UTF-8 so all surviving bytes are still valid UTF-8.
    String::from_utf8(out).unwrap_or_default().chars().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_produces_empty_chat_list_and_messages() {
        // Oracle: new() must produce empty chat_list and messages (no placeholder data).
        let state = AppState::new();
        assert!(
            state.chat_list.is_empty(),
            "chat_list must be empty at construction"
        );
        assert!(
            state.messages.is_empty(),
            "messages must be empty at construction"
        );
        assert!(
            state.chat_ids.is_empty(),
            "chat_ids must be empty at construction"
        );
        assert_eq!(state.selected_chat, 0);
        assert_eq!(state.input_cursor, 0);
        assert!(!state.quit);
    }

    #[test]
    fn clamp_scroll_reduces_oversized_offset() {
        // Oracle: with 20 messages and visible_height=5, max scroll = 15.
        let mut state = AppState::new();
        for i in 0..20 {
            state.messages.push_back(format!("msg {i}"));
        }
        state.scroll_offset = 100;
        state.clamp_scroll(5);
        assert_eq!(
            state.scroll_offset, 15,
            "scroll_offset must be clamped to messages.len()-visible_height"
        );
    }

    #[test]
    fn clamp_scroll_leaves_valid_offset_unchanged() {
        // Oracle: scroll_offset=3 with 20 messages and visible_height=5 is valid (max=15).
        let mut state = AppState::new();
        for i in 0..20 {
            state.messages.push_back(format!("msg {i}"));
        }
        state.scroll_offset = 3;
        state.clamp_scroll(5);
        assert_eq!(state.scroll_offset, 3);
    }

    #[test]
    fn clamp_scroll_with_few_messages_clamps_to_zero() {
        // Oracle: 3 messages and visible_height=5 → max=0; any offset clamps to 0.
        let mut state = AppState::new();
        state.messages.clear();
        for i in 0..3 {
            state.messages.push_back(format!("msg {i}"));
        }
        state.scroll_offset = 10;
        state.clamp_scroll(5);
        assert_eq!(state.scroll_offset, 0);
    }

    #[test]
    fn sanitize_display_identity() {
        assert_eq!(sanitize_display("normal text"), "normal text");
    }

    #[test]
    fn sanitize_display_strips_color_escape() {
        // Oracle: manual strip — "\x1b[31m" is ESC+[+31+m, "Red" is the visible content, "\x1b[0m" resets
        assert_eq!(sanitize_display("\x1b[31mRed\x1b[0m"), "Red");
    }

    #[test]
    fn sanitize_display_strips_middle_escape() {
        // Oracle: manual — "a", "b", "c" are the visible chars, "\x1b[5m" and "\x1b[0m" stripped
        assert_eq!(sanitize_display("a\x1b[5mb\x1b[0mc"), "abc");
    }

    #[test]
    fn sanitize_display_empty_string() {
        assert_eq!(sanitize_display(""), "");
    }

    // ── Extended sanitize_display tests (Bug 2 — KITH-hqrw.48) ──────────────
    // All oracles are manually constructed from known ANSI/VT100 escape sequences.
    // Reference: ECMA-48 §5.4 (CSI), §8.3.89 (OSC), VT100 User Guide.

    #[test]
    fn sanitize_display_strips_cursor_movement_csi() {
        // Oracle: ESC[A = cursor up (CSI, final byte 'A' = 0x41, in 0x40–0x7E).
        // Visible content: "AB". ESC[A must be discarded entirely.
        // Input: "A\x1b[AB" → strip ESC[A → "AB"
        assert_eq!(sanitize_display("A\x1b[AB"), "AB");
    }

    #[test]
    fn sanitize_display_strips_screen_clear_csi() {
        // Oracle: ESC[2J = erase display (CSI, parameter '2', final byte 'J' = 0x4A).
        // Input: "before\x1b[2Jafter" → strip ESC[2J → "beforeafter"
        assert_eq!(sanitize_display("before\x1b[2Jafter"), "beforeafter");
    }

    #[test]
    fn sanitize_display_strips_osc_with_bel_terminator() {
        // Oracle: ESC]0;title\x07 is the standard OSC for setting the terminal
        // window title (OSC 0 = icon name + title, terminated by BEL = 0x07).
        // Visible content: "text". The entire OSC sequence must be discarded.
        // Input: "\x1b]0;My Title\x07text" → strip OSC → "text"
        assert_eq!(sanitize_display("\x1b]0;My Title\x07text"), "text");
    }

    #[test]
    fn sanitize_display_strips_osc_with_st_terminator() {
        // Oracle: ESC]8;;url ESC\ is the OSC 8 hyperlink sequence terminated by
        // ST (String Terminator = ESC \). Both the OSC and its ST must be removed.
        // Input: "\x1b]8;;https://example.com\x1b\\link" → "link"
        assert_eq!(
            sanitize_display("\x1b]8;;https://example.com\x1b\\link"),
            "link"
        );
    }

    #[test]
    fn sanitize_display_strips_bare_esc_byte() {
        // Oracle: a bare ESC byte not followed by '[' or ']' (or at end of input)
        // is an unknown/incomplete escape. It must be discarded.
        // Input: "a\x1bb" — ESC followed by 'b' (not '[' or ']'); discard ESC only.
        // After discarding ESC: "ab"
        assert_eq!(sanitize_display("a\x1bb"), "ab");
    }

    #[test]
    fn new_state_initializes_send_fields() {
        // Oracle: should_send_message, error_notification, and unread_message_ids
        // start at their zero values.  message_ids and message_senders must be
        // parallel to messages (same length) — the invariant, not necessarily empty.
        let state = AppState::new();
        assert!(!state.should_send_message);
        assert!(state.error_notification.is_none());
        assert_eq!(
            state.message_ids.len(),
            state.messages.len(),
            "message_ids must be parallel to messages"
        );
        assert_eq!(
            state.message_senders.len(),
            state.messages.len(),
            "message_senders must be parallel to messages"
        );
        assert!(state.unread_message_ids.is_empty());
    }

    #[test]
    fn set_error_stores_message() {
        // Oracle: we set "oops" and expect "oops" back.
        let mut state = AppState::new();
        state.set_error("oops");
        let (msg, _) = state
            .error_notification
            .as_ref()
            .expect("error_notification must be Some");
        assert_eq!(msg, "oops");
    }

    #[test]
    fn clear_stale_error_clears_old_error() {
        // Oracle: 4s > 3s threshold, so the error must be cleared.
        let mut state = AppState::new();
        state.error_notification = Some((
            "old error".to_string(),
            std::time::Instant::now() - std::time::Duration::from_secs(4),
        ));
        state.clear_stale_error();
        assert!(state.error_notification.is_none());
    }

    #[test]
    fn clear_stale_error_keeps_fresh_error() {
        // Oracle: just-set error has ~0s elapsed, well under 3s threshold.
        let mut state = AppState::new();
        state.error_notification = Some(("fresh error".to_string(), std::time::Instant::now()));
        state.clear_stale_error();
        assert!(state.error_notification.is_some());
    }
}
