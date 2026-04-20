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
            ConnectionStatus::Reconnecting => write!(f, "Reconnecting"),
            ConnectionStatus::Error(_) => write!(f, "Error"),
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
    /// Construct initial state with hardcoded placeholder data.
    pub fn new() -> Self {
        let mut messages = VecDeque::new();
        for i in 1..=20u32 {
            messages.push_back(format!("12:{:02} alice: placeholder message {i}", i % 60));
        }
        AppState {
            quit: false,
            terminal_size: (80, 24),
            focus: Focus::Input,
            chat_list: vec![
                "alice".to_string(),
                "bob".to_string(),
                "group-chat".to_string(),
            ],
            chat_ids: vec![],
            selected_chat: 0,
            messages,
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

/// Strip ANSI SGR escape sequences (ESC `[` ... `m`) from `s` and return
/// only the visible characters.
///
/// The function is pure: no I/O, no side effects.
pub fn sanitize_display(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            // Skip ESC '[' and everything up to and including the next 'm'.
            i += 2;
            while i < bytes.len() {
                let b = bytes[i];
                i += 1;
                if b == b'm' {
                    break;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
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
    fn new_produces_nonempty_chat_list_and_messages() {
        // Oracle: hardcoded; new() must populate placeholder data.
        let state = AppState::new();
        assert!(!state.chat_list.is_empty(), "chat_list must be non-empty");
        assert!(!state.messages.is_empty(), "messages must be non-empty");
        assert_eq!(state.selected_chat, 0);
        assert_eq!(state.input_cursor, 0);
        assert!(!state.quit);
    }

    #[test]
    fn clamp_scroll_reduces_oversized_offset() {
        // Oracle: with 20 messages and visible_height=5, max scroll = 15.
        let mut state = AppState::new(); // 20 placeholder messages
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

    #[test]
    fn new_state_initializes_send_fields() {
        // Oracle: initial state is zero/empty (structural invariant).
        let state = AppState::new();
        assert!(!state.should_send_message);
        assert!(state.error_notification.is_none());
        assert!(state.message_ids.is_empty());
        assert!(state.message_senders.is_empty());
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
