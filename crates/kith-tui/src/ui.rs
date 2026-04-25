use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{AppState, Focus};

/// Render the full TUI layout into `f` using data from `state`.
///
/// Layout (vertical):
///   - top row (Fill): chat list (25%) | message thread (Fill)
///   - input row (Length 3): text input
///   - status row (Length 1): status bar
///
/// Yellow border on the focused panel. Cursor shown in input panel when focused.
///
/// Updates `state.last_message_panel_height` with the actual inner height of
/// the message panel so that scroll clamping in event.rs uses the same value
/// as rendering.
pub fn draw(f: &mut Frame, state: &mut AppState) {
    let area = f.area();
    if area.width < 4 || area.height < 4 {
        return;
    }

    let vertical = Layout::vertical([
        Constraint::Fill(1),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(area);

    let top_area = vertical[0];
    let input_area = vertical[1];
    let status_area = vertical[2];

    let horizontal =
        Layout::horizontal([Constraint::Percentage(25), Constraint::Fill(1)]).split(top_area);

    let chat_list_area = horizontal[0];
    let message_area = horizontal[1];

    draw_chat_list(f, state, chat_list_area);
    draw_messages(f, state, message_area);
    draw_input(f, state, input_area);
    draw_status(f, state, status_area);
}

fn border_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    }
}

fn draw_chat_list(f: &mut Frame, state: &AppState, area: ratatui::layout::Rect) {
    if area.width < 4 || area.height < 4 {
        return;
    }
    let focused = state.focus == Focus::ChatList;
    let block = Block::default()
        .title("Chats")
        .borders(Borders::ALL)
        .border_style(border_style(focused));

    let items: Vec<ListItem> = state
        .chat_list
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let style = if i == state.selected_chat {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            };
            ListItem::new(Span::raw(name.as_str())).style(style)
        })
        .collect();

    f.render_widget(List::new(items).block(block), area);
}

fn draw_messages(f: &mut Frame, state: &mut AppState, area: ratatui::layout::Rect) {
    if area.width < 4 || area.height < 4 {
        return;
    }
    let block = Block::default().title("Messages").borders(Borders::ALL);

    let inner_height = area.height.saturating_sub(2);
    state.last_message_panel_height = inner_height;
    let visible_height = inner_height as usize;
    let total = state.messages.len();
    let top = total
        .saturating_sub(visible_height)
        .saturating_sub(state.scroll_offset);

    let lines: Vec<Line> = state
        .messages
        .iter()
        .map(|m| Line::from(Span::raw(m.as_str())))
        .collect();

    f.render_widget(
        Paragraph::new(lines).block(block).scroll((top as u16, 0)),
        area,
    );
}

fn draw_input(f: &mut Frame, state: &AppState, area: ratatui::layout::Rect) {
    if area.width < 4 || area.height < 4 {
        return;
    }
    let focused = state.focus == Focus::Input;
    let block = Block::default()
        .title("Input")
        .borders(Borders::ALL)
        .border_style(border_style(focused));

    f.render_widget(
        Paragraph::new(Span::raw(state.input.as_str())).block(block),
        area,
    );

    if focused {
        // Clamp to u16::MAX before casting: input is capped at 65536 bytes so
        // the width can be 65536, which does not fit in u16 (max 65535).
        let col_width = UnicodeWidthStr::width(&state.input[..state.input_cursor]);
        let visible_cursor_col = u16::try_from(col_width).unwrap_or(u16::MAX);
        f.set_cursor_position((area.x + 1 + visible_cursor_col, area.y + 1));
    }
}

fn draw_status(f: &mut Frame, state: &AppState, area: ratatui::layout::Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let (text, style) = if let Some((msg, _)) = &state.error_notification {
        (
            format!(" ERR: {msg}"),
            Style::default().bg(Color::Red).fg(Color::White),
        )
    } else {
        let current_chat_name = state
            .chat_list
            .get(state.selected_chat)
            .map(|s| s.as_str())
            .unwrap_or("");
        (
            format!(" {} | {}", state.connection_status, current_chat_name),
            Style::default().bg(Color::DarkGray),
        )
    };
    f.render_widget(Paragraph::new(Span::raw(text)).style(style), area);
}

/// Truncate `s` to fit within `max` terminal display columns.
///
/// Counts display columns using `unicode_width`, so wide characters (CJK,
/// emoji) count as 2 columns each. Multi-byte characters that render as a
/// single column (e.g. `é`) count as 1.
///
/// - `max == 0`: returns empty string.
/// - `max == 1`: returns the first character (no room for an ellipsis).
/// - `max >= 2`: if `s` is wider than `max` columns, truncates to `max-1`
///   columns and appends `…` (U+2026, one display column).
/// - If `s` fits within `max` columns, returns `s` unchanged.
pub fn fit_col(s: &str, max: usize) -> String {
    let total_width = s.width();
    if total_width <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max == 1 {
        // Return the first character even if it is wide (no better option).
        return s.chars().next().map(|c| c.to_string()).unwrap_or_default();
    }
    // max >= 2: build truncated string by display columns, then append ellipsis.
    // Reserve 1 column for '…'.
    let target = max - 1;
    let mut result = String::new();
    let mut cols_used = 0usize;
    for c in s.chars() {
        let cw = UnicodeWidthChar::width(c).unwrap_or(1);
        if cols_used + cw > target {
            break;
        }
        result.push(c);
        cols_used += cw;
    }
    result.push('…');
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn draw_does_not_panic_80x24() {
        // Oracle: TestBackend at standard size; no panic = pass.
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        terminal.draw(|f| draw(f, &mut state)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_20x10() {
        // Oracle: TestBackend at minimum area; no panic = pass.
        let backend = TestBackend::new(20, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        terminal.draw(|f| draw(f, &mut state)).unwrap();
    }

    #[test]
    fn draw_status_shows_error_notification() {
        // Oracle: when error_notification is Some, status row must contain "ERR"
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.set_error("Send failed");
        terminal.draw(|f| draw(f, &mut state)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let status_row: String = (0..80)
            .map(|x| {
                buf.cell((x, 23))
                    .unwrap()
                    .symbol()
                    .chars()
                    .next()
                    .unwrap_or(' ')
            })
            .collect();
        assert!(
            status_row.contains("ERR"),
            "status bar must show ERR prefix when error_notification is set, got: {status_row:?}"
        );
    }

    #[test]
    fn draw_status_shows_connecting() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new(); // connection_status starts as Connecting
        terminal.draw(|f| draw(f, &mut state)).unwrap();
        let buf = terminal.backend().buffer().clone();
        // Last row should contain "Connecting" text
        let status_row: String = (0..80)
            .map(|x| {
                buf.cell((x, 23))
                    .unwrap()
                    .symbol()
                    .chars()
                    .next()
                    .unwrap_or(' ')
            })
            .collect();
        assert!(
            status_row.contains("Connecting"),
            "status bar should show Connecting, got: {status_row:?}"
        );
    }

    #[test]
    fn draw_status_shows_error_inner_string() {
        // Oracle: ConnectionStatus::Error("disk full") must show "disk full" in status bar.
        // Before the fix, Display only wrote "Error" and the inner string was dropped.
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.connection_status = crate::app::ConnectionStatus::Error("disk full".to_string());
        terminal.draw(|f| draw(f, &mut state)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let status_row: String = (0..80)
            .map(|x| {
                buf.cell((x, 23))
                    .unwrap()
                    .symbol()
                    .chars()
                    .next()
                    .unwrap_or(' ')
            })
            .collect();
        assert!(
            status_row.contains("disk full"),
            "status bar must show error inner string, got: {status_row:?}"
        );
    }

    #[test]
    fn draw_status_reconnecting_shows_retry_hint() {
        // Oracle: Reconnecting status must show retry hint so user knows it will self-recover.
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.connection_status = crate::app::ConnectionStatus::Reconnecting;
        terminal.draw(|f| draw(f, &mut state)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let status_row: String = (0..80)
            .map(|x| {
                buf.cell((x, 23))
                    .unwrap()
                    .symbol()
                    .chars()
                    .next()
                    .unwrap_or(' ')
            })
            .collect();
        assert!(
            status_row.contains("retry"),
            "status bar must show retry hint when Reconnecting, got: {status_row:?}"
        );
    }

    // fit_col tests — all oracles are manually constructed from the spec.

    #[test]
    fn fit_col_max_zero_returns_empty() {
        // Oracle: max=0 → no characters can fit → empty string.
        assert_eq!(fit_col("hello", 0), "");
        assert_eq!(fit_col("", 0), "");
    }

    #[test]
    fn fit_col_max_one_long_string_returns_first_char() {
        // Oracle: max=1, "hello" (5 chars) → "h" (first char, no ellipsis room).
        assert_eq!(fit_col("hello", 1), "h");
    }

    #[test]
    fn fit_col_max_one_single_char_unchanged() {
        // Oracle: max=1, "x" (1 char) fits exactly → "x".
        assert_eq!(fit_col("x", 1), "x");
    }

    #[test]
    fn fit_col_fits_exactly_unchanged() {
        // Oracle: "abc" is 3 chars, max=3 → fits, returned unchanged.
        assert_eq!(fit_col("abc", 3), "abc");
    }

    #[test]
    fn fit_col_shorter_than_max_unchanged() {
        // Oracle: "hi" is 2 chars, max=10 → fits, returned unchanged.
        assert_eq!(fit_col("hi", 10), "hi");
    }

    #[test]
    fn fit_col_empty_string_unchanged() {
        // Oracle: "" is 0 chars, any max → fits, returned unchanged.
        assert_eq!(fit_col("", 5), "");
        assert_eq!(fit_col("", 1), "");
    }

    #[test]
    fn fit_col_max_two_truncates_with_ellipsis() {
        // Oracle: "hello" (5 chars), max=2 → "h" + "…" = "h…".
        assert_eq!(fit_col("hello", 2), "h…");
    }

    #[test]
    fn fit_col_max_four_truncates_with_ellipsis() {
        // Oracle: "hello" (5 chars), max=4 → "hel" + "…" = "hel…".
        assert_eq!(fit_col("hello", 4), "hel…");
    }

    #[test]
    fn fit_col_multibyte_chars_counted_by_char_not_byte() {
        // Oracle: "héllo" is 5 chars (é is one char, two bytes).
        // max=3 → "hé" + "…" = "hé…" (3 chars output).
        assert_eq!(fit_col("héllo", 3), "hé…");
        // max=5 → fits exactly, returned unchanged.
        assert_eq!(fit_col("héllo", 5), "héllo");
    }

    #[test]
    fn fit_col_max_one_multibyte_first_char() {
        // Oracle: "élan" (4 chars), max=1 → "é" (first char only).
        assert_eq!(fit_col("élan", 1), "é");
    }

    #[test]
    fn fit_col_wide_chars_counted_by_display_columns() {
        // Oracle: "你好ABC" — '你' and '好' are each 2 display columns.
        // Total display width = 2+2+1+1+1 = 7.
        // max=4 → reserve 1 col for '…', so 3 cols available.
        // '你' = 2 cols → fits (2 ≤ 3). '好' = 2 cols → 2+2=4 > 3 → stop.
        // Result: "你…" (3 display cols).
        assert_eq!(fit_col("你好ABC", 4), "你…");

        // max=5 → reserve 1 col for '…', 4 cols available.
        // '你' = 2, '好' = 2 → 4 ≤ 4 → include both.
        // 'A' → 4+1=5 > 4 → stop.
        // Result: "你好…" (5 display cols).
        assert_eq!(fit_col("你好ABC", 5), "你好…");

        // max=7 → fits exactly → returned unchanged.
        assert_eq!(fit_col("你好ABC", 7), "你好ABC");
    }
}
