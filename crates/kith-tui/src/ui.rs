use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use unicode_width::UnicodeWidthStr;

use crate::app::{AppState, Focus};

/// Render the full TUI layout into `f` using data from `state`.
///
/// Layout (vertical):
///   - top row (Fill): chat list (25%) | message thread (Fill)
///   - input row (Length 3): text input
///   - status row (Length 1): status bar
///
/// Yellow border on the focused panel. Cursor shown in input panel when focused.
pub fn draw(f: &mut Frame, state: &AppState) {
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

fn draw_messages(f: &mut Frame, state: &AppState, area: ratatui::layout::Rect) {
    if area.width < 4 || area.height < 4 {
        return;
    }
    let block = Block::default().title("Messages").borders(Borders::ALL);

    let visible_height = area.height.saturating_sub(2) as usize;
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
        let state = AppState::new();
        terminal.draw(|f| draw(f, &state)).unwrap();
    }

    #[test]
    fn draw_does_not_panic_20x10() {
        // Oracle: TestBackend at minimum area; no panic = pass.
        let backend = TestBackend::new(20, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal.draw(|f| draw(f, &state)).unwrap();
    }

    #[test]
    fn draw_status_shows_error_notification() {
        // Oracle: when error_notification is Some, status row must contain "ERR"
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.set_error("Send failed");
        terminal.draw(|f| draw(f, &state)).unwrap();
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
        let state = AppState::new(); // connection_status starts as Connecting
        terminal.draw(|f| draw(f, &state)).unwrap();
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
}
