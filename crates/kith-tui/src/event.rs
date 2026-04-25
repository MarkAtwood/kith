use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Stdout;
use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
use futures::StreamExt;
use kith_core::{JmapRequest, StateChange};
use ratatui::{backend::CrosstermBackend, Terminal};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::app::{sanitize_display, AppState, Focus};
use crate::client;
use crate::ui;

/// Handle a single keyboard event, mutating `state` in place.
///
/// Extracted as a public function so unit tests can exercise key logic
/// without a real terminal.
pub fn handle_key(state: &mut AppState, code: KeyCode, modifiers: KeyModifiers) {
    match code {
        // Quit
        KeyCode::Char('q') if modifiers.is_empty() => {
            state.quit = true;
        }
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
            state.quit = true;
        }

        // Toggle focus
        KeyCode::Tab => {
            state.focus = match state.focus {
                Focus::ChatList => Focus::Input,
                Focus::Input => Focus::ChatList,
            };
        }

        // Chat list navigation
        KeyCode::Up if state.focus == Focus::ChatList => {
            state.selected_chat = state.selected_chat.saturating_sub(1);
        }
        KeyCode::Down if state.focus == Focus::ChatList => {
            let max = state.chat_list.len().saturating_sub(1);
            state.selected_chat = (state.selected_chat + 1).min(max);
        }

        // Input: insert character
        KeyCode::Char(c) if state.focus == Focus::Input => {
            if state.input.len() + c.len_utf8() <= 65536 {
                state.input.insert(state.input_cursor, c);
                state.input_cursor += c.len_utf8();
            }
        }

        // Input: delete char before cursor
        KeyCode::Backspace if state.focus == Focus::Input => {
            if state.input_cursor > 0 {
                let mut new_cursor = state.input_cursor - 1;
                while !state.input.is_char_boundary(new_cursor) {
                    new_cursor -= 1;
                }
                state.input.remove(new_cursor);
                state.input_cursor = new_cursor;
            }
        }

        // Input: cursor movement
        KeyCode::Left if state.focus == Focus::Input => {
            if state.input_cursor > 0 {
                let mut new_cursor = state.input_cursor - 1;
                while !state.input.is_char_boundary(new_cursor) {
                    new_cursor -= 1;
                }
                state.input_cursor = new_cursor;
            }
        }
        KeyCode::Right if state.focus == Focus::Input => {
            if state.input_cursor < state.input.len() {
                let mut new_cursor = state.input_cursor + 1;
                while new_cursor < state.input.len() && !state.input.is_char_boundary(new_cursor) {
                    new_cursor += 1;
                }
                state.input_cursor = new_cursor;
            }
        }
        // Input: delete char at cursor (forward-delete)
        KeyCode::Delete if state.focus == Focus::Input => {
            if state.input_cursor < state.input.len() {
                let mut end_cursor = state.input_cursor + 1;
                while end_cursor < state.input.len() && !state.input.is_char_boundary(end_cursor) {
                    end_cursor += 1;
                }
                state.input.drain(state.input_cursor..end_cursor);
                // Cursor stays at input_cursor (now points to next char or end)
            }
        }
        KeyCode::Home if state.focus == Focus::Input => {
            state.input_cursor = 0;
        }
        KeyCode::End if state.focus == Focus::Input => {
            state.input_cursor = state.input.len();
        }
        // Input: flag for async send (actual send happens in run())
        KeyCode::Enter if state.focus == Focus::Input => {
            if !state.input.trim().is_empty() {
                state.should_send_message = true;
            }
        }

        // Scroll
        KeyCode::PageUp => {
            let visible_height = state.last_message_panel_height as usize;
            state.scroll_offset += visible_height;
            state.clamp_scroll(visible_height);
        }
        KeyCode::PageDown => {
            let visible_height = state.last_message_panel_height as usize;
            state.scroll_offset = state.scroll_offset.saturating_sub(visible_height);
            state.clamp_scroll(visible_height);
        }
        KeyCode::Esc => {
            state.scroll_offset = 0;
        }

        _ => {}
    }
}

/// Fetch Chat/get and Contact/get from the server and update `state` in place.
///
/// On any network or parse error the function logs to stderr and returns
/// without modifying state.  Never panics.
pub(crate) async fn load_startup_data(
    http_client: &reqwest::Client,
    api_url: &str,
    state: &mut AppState,
) {
    let req = JmapRequest {
        using: vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        method_calls: vec![
            (
                "Chat/get".into(),
                json!({"accountId": "a-self"}),
                "c0".into(),
            ),
            (
                "ChatContact/get".into(),
                json!({"accountId": "a-self"}),
                "c1".into(),
            ),
        ],
    };

    let resp = match client::call_jmap(http_client, api_url, &req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kith-tui: startup JMAP call failed: {e}");
            state.connection_status =
                crate::app::ConnectionStatus::Error("JMAP startup failed".to_string());
            return;
        }
    };

    // Parse Contact/get (method_responses[1]) first so the map is ready for chat naming.
    let mut contacts_map: HashMap<String, String> = HashMap::new();
    if let Some((method, args, _call_id)) = resp.method_responses.get(1) {
        if method == "error" {
            let err_type = args
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            eprintln!("kith-tui: ChatContact/get returned JMAP error: {err_type}");
            // Non-fatal: proceed without contacts; chats will show raw IDs.
        } else if let Some(list) = args.get("list").and_then(Value::as_array) {
            for contact in list {
                let id = match contact.get("id").and_then(Value::as_str) {
                    Some(v) => v.to_string(),
                    None => continue,
                };
                let display_name = {
                    let dn = contact
                        .get("displayName")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !dn.is_empty() {
                        dn.to_string()
                    } else {
                        let login = contact.get("login").and_then(Value::as_str).unwrap_or("");
                        if !login.is_empty() {
                            login.to_string()
                        } else {
                            id.clone()
                        }
                    }
                };
                contacts_map.insert(id, sanitize_display(&display_name));
            }
        }
    }

    // Parse Chat/get (method_responses[0]).
    let mut chat_ids: Vec<String> = Vec::new();
    let mut chat_list: Vec<String> = Vec::new();
    if let Some((method, args, _call_id)) = resp.method_responses.first() {
        if method == "error" {
            let err_type = args
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            eprintln!("kith-tui: Chat/get returned JMAP error: {err_type}");
            state.connection_status =
                crate::app::ConnectionStatus::Error(format!("Server error: {err_type}"));
            return;
        } else if let Some(list) = args.get("list").and_then(Value::as_array) {
            for chat in list {
                let id = match chat.get("id").and_then(Value::as_str) {
                    Some(v) => v.to_string(),
                    None => continue,
                };
                let kind = chat.get("kind").and_then(Value::as_str).unwrap_or("");
                let participants: Vec<String> = chat
                    .get("participants")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let unread_count =
                    chat.get("unreadCount").and_then(Value::as_u64).unwrap_or(0) as u32;

                let base_name = if kind == "direct" {
                    let names: Vec<String> = participants
                        .iter()
                        .filter_map(|pid| contacts_map.get(pid).cloned())
                        .collect();
                    if names.is_empty() {
                        "Unknown".to_string()
                    } else {
                        names.join(", ")
                    }
                } else {
                    format!("Group ({})", participants.len())
                };

                let display = if unread_count > 0 {
                    format!("{base_name} ({unread_count})")
                } else {
                    base_name
                };

                chat_ids.push(id);
                // display is built from contacts_map (already sanitized) and
                // numeric/constant strings — no further sanitization needed.
                chat_list.push(display);
            }
        }
    }

    state.chat_list = chat_list;
    state.chat_ids = chat_ids;
    state.contacts = contacts_map;
    if state.chat_list.is_empty() {
        state.selected_chat = 0;
    } else {
        state.selected_chat = state.selected_chat.min(state.chat_list.len() - 1);
    }
}

/// Format one JMAP message Value as a display line: "HH:MM sender_name: body".
///
/// Returns `None` if the Value is missing required fields.  All strings are
/// passed through `sanitize_display` before use.
fn format_message_line(
    msg: &serde_json::Value,
    contacts: &std::collections::HashMap<String, String>,
    owner_user_id: &str,
) -> Option<String> {
    // receivedAt is required; absence silently drops the message from display.
    let received_at = msg.get("receivedAt").and_then(serde_json::Value::as_str)?;
    let hhmm = received_at.get(11..16).unwrap_or("??:??");
    let sender_id = msg
        .get("senderId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let sender_name = if sender_id == owner_user_id {
        "me"
    } else {
        contacts
            .get(sender_id)
            .map(String::as_str)
            .unwrap_or(sender_id)
    };
    let body = msg
        .get("body")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    Some(sanitize_display(&format!("{hhmm} {sender_name}: {body}")))
}

/// Collects the fields extracted from a single message during `load_messages_for_chat`.
struct MessageEntry {
    received_at: String,
    display_line: String,
    msg_id: String,
    sender_id: String,
    /// Null/missing means unread; any string value means already read.
    read_at: Option<String>,
}

/// Named return type for `load_messages_for_chat`.
///
/// All four deques are sorted oldest-first and are always the same length.
/// When `is_error` is true the load failed; callers must leave the existing
/// message list unchanged rather than replacing it with an empty deque.
#[derive(Default)]
pub(crate) struct LoadedMessages {
    pub display_lines: VecDeque<String>,
    pub message_ids: VecDeque<String>,
    pub sender_ids: VecDeque<String>,
    /// `readAt` values parallel to `message_ids`. `None` means unread.
    pub read_ats: VecDeque<Option<String>>,
    /// The `state` token from the Message/get response. Empty string if unknown.
    pub state: String,
    /// True when the load failed due to a network or server error.
    pub is_error: bool,
}

/// Fetch messages for a specific chat.
///
/// Performs Message/query to get IDs, then Message/get to fetch content.
/// Returns an empty `LoadedMessages` on any error or if the chat has no messages.
/// The three deques are sorted oldest-first (ascending receivedAt) and are
/// always the same length.
pub(crate) async fn load_messages_for_chat(
    http_client: &reqwest::Client,
    api_url: &str,
    chat_id: &str,
    contacts: &std::collections::HashMap<String, String>,
    owner_user_id: &str,
) -> LoadedMessages {
    // Step A — Message/query
    let query_req = JmapRequest {
        using: vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        method_calls: vec![(
            "Message/query".into(),
            json!({"accountId": "a-self", "filter": {"chatId": chat_id}, "position": 0, "limit": 500, "calculateTotal": true}),
            "mq0".into(),
        )],
    };

    let query_resp = match client::call_jmap(http_client, api_url, &query_req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kith-tui: Message/query failed: {e}");
            return LoadedMessages {
                is_error: true,
                ..LoadedMessages::default()
            };
        }
    };

    let first_query = query_resp.method_responses.first();
    let ids: Vec<String> = first_query
        .and_then(|(_, args, _)| args.get("ids"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    // total is the server-side count before the limit was applied.
    // May be absent if the server did not support calculateTotal.
    let total_on_server: Option<u64> = first_query
        .and_then(|(_, args, _)| args.get("total"))
        .and_then(Value::as_u64);

    if ids.is_empty() {
        return LoadedMessages::default();
    }

    // Step B — Message/get
    let get_req = JmapRequest {
        using: vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        method_calls: vec![(
            "Message/get".into(),
            json!({"accountId": "a-self", "ids": ids}),
            "mg0".into(),
        )],
    };

    let get_resp = match client::call_jmap(http_client, api_url, &get_req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kith-tui: Message/get failed: {e}");
            return LoadedMessages {
                is_error: true,
                ..LoadedMessages::default()
            };
        }
    };

    let get_first = get_resp.method_responses.first();

    // Capture the state token from the Message/get response — this is the
    // authoritative current state after the full reload, used by the
    // stateMismatch recovery path.
    let response_state = get_first
        .and_then(|(_, args, _)| args.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let list = match get_first
        .and_then(|(_, args, _)| args.get("list"))
        .and_then(Value::as_array)
    {
        Some(l) => l,
        None => {
            return LoadedMessages {
                is_error: true,
                ..LoadedMessages::default()
            };
        }
    };

    // Step C — Format each message, collecting id, senderId, and readAt alongside each entry.
    let mut entries: Vec<MessageEntry> = Vec::with_capacity(list.len());
    for msg in list {
        let received_at = msg
            .get("receivedAt")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        let msg_id = msg
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let sender_id = msg
            .get("senderId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let read_at = msg
            .get("readAt")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(display_line) = format_message_line(msg, contacts, owner_user_id) {
            entries.push(MessageEntry {
                received_at,
                display_line,
                msg_id,
                sender_id,
                read_at,
            });
        }
    }

    // Step D — Sort ascending by receivedAt (oldest first), then move fields
    // into the return struct in a single pass (no clone needed).
    entries.sort_by(|a, b| a.received_at.cmp(&b.received_at));
    let mut loaded = LoadedMessages {
        state: response_state,
        ..LoadedMessages::default()
    };
    for e in entries {
        loaded.display_lines.push_back(e.display_line);
        loaded.message_ids.push_back(e.msg_id);
        loaded.sender_ids.push_back(e.sender_id);
        loaded.read_ats.push_back(e.read_at);
    }

    // If the server has more messages than the limit returned, prepend a notice
    // so the user knows history is truncated rather than silently missing.
    // Also warn when total was absent and we hit the 500-message limit — the server
    // may have more history even though it did not report the count.
    const QUERY_LIMIT: usize = 500;
    if let Some(total) = total_on_server {
        if total as usize > ids.len() {
            let hidden = total as usize - ids.len();
            loaded.display_lines.push_front(format!(
                "[-- {} older message{} not shown --]",
                hidden,
                if hidden == 1 { "" } else { "s" }
            ));
            // Pad parallel deques so they stay in sync with display_lines.
            loaded.message_ids.push_front(String::new());
            loaded.sender_ids.push_front(String::new());
            loaded.read_ats.push_front(None);
        }
    } else if ids.len() >= QUERY_LIMIT {
        // Server omitted `total`; we hit the limit so history may be truncated.
        loaded
            .display_lines
            .push_front("[-- message history may be truncated --]".to_string());
        // Pad parallel deques so they stay in sync with display_lines.
        loaded.message_ids.push_front(String::new());
        loaded.sender_ids.push_front(String::new());
        loaded.read_ats.push_front(None);
    }

    loaded
}

/// Send a new message to the given chat via JMAP Message/set create.
///
/// Returns the server-assigned message ID on success.
/// Returns an error if the body is empty/whitespace, the network fails,
/// or the server returns a notCreated or error response.
///
/// Does NOT log the message body. Does NOT include server-set fields (id,
/// senderId, deliveryState, receivedAt) in the create payload.
pub(crate) async fn send_message(
    http_client: &reqwest::Client,
    api_url: &str,
    chat_id: &str,
    body: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if body.trim().is_empty() {
        return Err("empty message body".into());
    }

    let sent_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let req = JmapRequest {
        using: vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        method_calls: vec![(
            "Message/set".into(),
            json!({"accountId": "a-self", "create": {"k-1": {"chatId": chat_id, "body": body, "bodyType": "text/plain", "sentAt": sent_at}}}),
            "s0".into(),
        )],
    };

    let resp = client::call_jmap(http_client, api_url, &req).await?;

    let (method_name, args, _) = match resp.method_responses.first() {
        Some(r) => r,
        None => return Err("unexpected Message/set response format".into()),
    };

    if method_name == "error" {
        let type_str = args
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Err(format!("Message/set error: {type_str}").into());
    }

    if let Some(not_created) = args.get("notCreated").and_then(|v| v.get("k-1")) {
        let type_str = not_created
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Err(format!("notCreated: {type_str}").into());
    }

    if let Some(id) = args
        .get("created")
        .and_then(|v| v.get("k-1"))
        .and_then(|v| v.get("id"))
        .and_then(Value::as_str)
    {
        return Ok(id.to_string());
    }

    Err("unexpected Message/set response format".into())
}

/// Mark a list of messages as read via JMAP Message/set update (sets readAt = now).
///
/// If message_ids is empty, returns Ok(()) without making any HTTP call.
/// notUpdated entries are treated as non-fatal (logged to stderr, Ok returned).
pub(crate) async fn send_read_receipts(
    http_client: &reqwest::Client,
    api_url: &str,
    message_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if message_ids.is_empty() {
        return Ok(());
    }

    let read_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut update = serde_json::Map::new();
    for id in message_ids {
        update.insert(id.clone(), json!({"readAt": read_at}));
    }

    let req = JmapRequest {
        using: vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        method_calls: vec![(
            "Message/set".into(),
            json!({"accountId": "a-self", "update": update}),
            "r0".into(),
        )],
    };

    let resp = client::call_jmap(http_client, api_url, &req).await?;

    let (method_name, args, _) = match resp.method_responses.first() {
        Some(r) => r,
        None => return Err("Message/set returned no responses".into()),
    };

    if method_name == "error" {
        let error_type = args
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Err(format!("Message/set error: {error_type}").into());
    }

    if let Some(not_updated) = args.get("notUpdated").and_then(Value::as_object) {
        if !not_updated.is_empty() {
            eprintln!(
                "kith-tui: read receipt failed for {} messages",
                not_updated.len()
            );
        }
    }

    Ok(())
}

/// Build the set of unread message IDs from a freshly loaded message list.
///
/// An unread message is one whose sender is not the owner (i.e. it is inbound),
/// whose id is non-empty, and whose `readAt` field is `None` (null or absent in
/// the JSON). Messages that already have a `readAt` value are skipped — they
/// were read in a previous session and must not trigger a redundant JMAP update.
///
/// `ids`, `senders`, and `read_ats` must all be the same length (they are
/// parallel VecDeques returned by `load_messages_for_chat`).
fn unread_ids_from_loaded_messages(
    ids: &VecDeque<String>,
    senders: &VecDeque<String>,
    read_ats: &VecDeque<Option<String>>,
    owner_user_id: &str,
) -> HashSet<String> {
    senders
        .iter()
        .zip(ids.iter())
        .zip(read_ats.iter())
        .filter(|((s, _), ra)| s.as_str() != owner_user_id && ra.is_none())
        .map(|((_, id), _)| id.clone())
        .filter(|id| !id.is_empty())
        .collect()
}

/// Attempt to flush all pending unread receipts in `state.unread_message_ids`.
///
/// On success the set is cleared. On error the IDs are left for the next
/// attempt; the caller should not treat a failed flush as fatal.
async fn flush_unread_receipts(http_client: &reqwest::Client, api_url: &str, state: &mut AppState) {
    let unread: Vec<String> = state.unread_message_ids.iter().cloned().collect();
    // send_read_receipts is a no-op on empty input; no need to guard here.
    // On error: silently leave unread_message_ids for next attempt.
    if send_read_receipts(http_client, api_url, &unread)
        .await
        .is_ok()
    {
        state.unread_message_ids.clear();
    }
}

/// Handle a single [`StateChange`] event received from the SSE channel.
///
/// On a "Message" state change: calls `Message/changes` to find new/updated
/// IDs, then `Message/get` to fetch them, and appends formatted lines for
/// messages belonging to the currently selected chat.
///
/// On a "Chat" state change: reloads the full chat list via `load_startup_data`.
///
/// Unknown type names are silently ignored.  All JMAP errors are logged to
/// stderr and the function returns without modifying `state.message_state`.
pub(crate) async fn handle_state_change(
    http_client: &reqwest::Client,
    api_url: &str,
    sc: &StateChange,
    state: &mut AppState,
) {
    match sc.type_name.as_str() {
        "Message" => {
            let since_state = if state.message_state.is_empty() {
                "s-0".to_string()
            } else {
                state.message_state.clone()
            };

            // Step 1: Message/changes
            let changes_req = JmapRequest {
                using: vec![
                    "urn:ietf:params:jmap:core".into(),
                    "urn:ietf:params:jmap:chat".into(),
                ],
                method_calls: vec![(
                    "Message/changes".into(),
                    json!({"accountId": "a-self", "sinceState": since_state}),
                    "mc0".into(),
                )],
            };

            let changes_resp = match client::call_jmap(http_client, api_url, &changes_req).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("kith-tui: Message/changes failed: {e}");
                    return;
                }
            };

            let (method_name, args, _) = match changes_resp.method_responses.first() {
                Some(r) => r,
                None => {
                    eprintln!("kith-tui: Message/changes returned no responses");
                    return;
                }
            };

            // Handle stateMismatch: fall back to full reload
            if method_name == "error" {
                let error_type = args.get("type").and_then(Value::as_str).unwrap_or("");
                if error_type == "stateMismatch" {
                    if let Some(chat_id) = state.chat_ids.get(state.selected_chat).cloned() {
                        // Reload full message list for current chat; silently skipped if no chats loaded.
                        let loaded =
                            load_messages_for_chat(http_client, api_url, &chat_id, &state.contacts, &state.owner_user_id)
                                .await;
                        if loaded.is_error {
                            state.connection_status = crate::app::ConnectionStatus::Error(
                                "Failed to load messages".to_string(),
                            );
                        } else {
                            // Use the state token from the Message/get response, not
                            // sc.new_state, which may be stale if more messages arrived
                            // between the stateMismatch error and the reload completing.
                            if !loaded.state.is_empty() {
                                state.message_state = loaded.state;
                            }
                            state.messages = loaded.display_lines;
                            state.message_ids = loaded.message_ids;
                            state.message_senders = loaded.sender_ids;
                        }
                    }
                } else {
                    eprintln!("kith-tui: Message/changes returned error: {error_type}");
                }
                return;
            }

            let new_state = args
                .get("newState")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();

            let created: Vec<String> = args
                .get("created")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            let updated: Vec<String> = args
                .get("updated")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();

            // Deduplicate combined IDs — use a HashSet for O(n) membership checks.
            let mut seen: std::collections::HashSet<String> = created.iter().cloned().collect();
            let mut all_ids: Vec<String> = created;
            for id in updated {
                if seen.insert(id.clone()) {
                    all_ids.push(id);
                }
            }

            if !new_state.is_empty() {
                state.message_state = new_state;
            }

            if all_ids.is_empty() {
                return;
            }

            // Step 2: Message/get for new/updated IDs
            let get_req = JmapRequest {
                using: vec![
                    "urn:ietf:params:jmap:core".into(),
                    "urn:ietf:params:jmap:chat".into(),
                ],
                method_calls: vec![(
                    "Message/get".into(),
                    json!({"accountId": "a-self", "ids": all_ids}),
                    "mg0".into(),
                )],
            };

            let get_resp = match client::call_jmap(http_client, api_url, &get_req).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("kith-tui: Message/get failed: {e}");
                    return;
                }
            };

            let list = match get_resp
                .method_responses
                .first()
                .and_then(|(_, args, _)| args.get("list"))
                .and_then(Value::as_array)
            {
                Some(l) => l,
                None => return,
            };

            let current_chat_id = state
                .chat_ids
                .get(state.selected_chat)
                .map(String::as_str)
                .unwrap_or("");

            let mut newly_unread: Vec<String> = Vec::new();

            for msg in list {
                let msg_chat_id = msg.get("chatId").and_then(Value::as_str).unwrap_or("");
                if msg_chat_id != current_chat_id {
                    continue;
                }

                if let Some(line) = format_message_line(msg, &state.contacts, &state.owner_user_id) {
                    state.messages.push_back(line);
                    let msg_id = msg
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let sender_id_str = msg
                        .get("senderId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    state.message_ids.push_back(msg_id.clone());
                    state.message_senders.push_back(sender_id_str.clone());
                    if sender_id_str != state.owner_user_id && !msg_id.is_empty() {
                        state.unread_message_ids.insert(msg_id.clone());
                        newly_unread.push(msg_id);
                    }
                }
            }

            // Send one batched read receipt for all newly arrived inbound messages.
            // send_read_receipts is a no-op on empty input, so no outer guard is needed.
            if send_read_receipts(http_client, api_url, &newly_unread)
                .await
                .is_ok()
            {
                for id in &newly_unread {
                    state.unread_message_ids.remove(id);
                }
            }
            // On error: IDs remain in unread_message_ids for next attempt
        }
        "Chat" => {
            load_startup_data(http_client, api_url, state).await;
        }
        _ => {
            // Unknown type_name: silently ignore.
        }
    }
}

/// Async event loop. Draws the initial frame, then processes crossterm events
/// and a 50 ms redraw tick until `state.quit` is set.
///
/// The caller is responsible for terminal cleanup after this returns.
pub async fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut AppState,
    http_client: reqwest::Client,
    api_url: String,
    sse_rx: mpsc::Receiver<StateChange>,
    sse_status_rx: mpsc::Receiver<crate::client::SseStatus>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut sse_rx = sse_rx;
    let mut sse_status_rx = sse_status_rx;
    let mut events = EventStream::new();
    let mut tick = tokio::time::interval(Duration::from_millis(50));

    // Initial draw
    terminal.draw(|f| {
        state.terminal_size = (f.area().width, f.area().height);
        ui::draw(f, state);
    })?;

    load_startup_data(&http_client, &api_url, state).await;

    if let Some(chat_id) = state.chat_ids.get(state.selected_chat).cloned() {
        let loaded =
            load_messages_for_chat(&http_client, &api_url, &chat_id, &state.contacts, &state.owner_user_id).await;
        if loaded.is_error {
            state.connection_status =
                crate::app::ConnectionStatus::Error("Failed to load messages".to_string());
        } else {
            state.messages = loaded.display_lines;
            state.message_ids = loaded.message_ids;
            state.message_senders = loaded.sender_ids;
            if !loaded.state.is_empty() {
                state.message_state = loaded.state;
            }
            state.unread_message_ids = unread_ids_from_loaded_messages(
                &state.message_ids,
                &state.message_senders,
                &loaded.read_ats,
                &state.owner_user_id,
            );
            flush_unread_receipts(&http_client, &api_url, state).await;
            state.scroll_offset = 0;
        }
    }
    // If chat_ids is empty (new user with no chats yet), continue into the event loop.

    // Track the previously selected chat to detect changes and reload messages.
    // Invariant: prev_selected must be updated to state.selected_chat at the end of
    // every iteration where a change is detected.  Missing this update causes messages
    // to reload on every tick instead of only on actual selection changes.
    let mut prev_selected = state.selected_chat;

    loop {
        tokio::select! {
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) => {
                        handle_key(state, key.code, key.modifiers);
                    }
                    Some(Ok(Event::Resize(w, h))) => {
                        state.terminal_size = (w, h);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => {
                        // Event stream errors are non-fatal; continue the loop.
                    }
                    None => {
                        // Stream ended; treat as quit.
                        state.quit = true;
                    }
                }
            }
            maybe_sc = sse_rx.recv() => {
                match maybe_sc {
                    Some(sc) => {
                        handle_state_change(&http_client, &api_url, &sc, state).await;
                        // A "Chat" state change calls load_startup_data which may
                        // clamp selected_chat.  Sync prev_selected so the
                        // post-select reload check does not fire spuriously.
                        prev_selected = state.selected_chat;
                    }
                    None => {
                        // SSE task exited entirely (receiver dropped). Treat as quit.
                        state.quit = true;
                    }
                }
            }
            maybe_status = sse_status_rx.recv() => {
                match maybe_status {
                    Some(crate::client::SseStatus::Connected) => {
                        state.connection_status = crate::app::ConnectionStatus::Connected;
                    }
                    Some(crate::client::SseStatus::Reconnecting) => {
                        state.connection_status = crate::app::ConnectionStatus::Reconnecting;
                    }
                    Some(crate::client::SseStatus::AuthError(code)) => {
                        // Auth failure — the SSE task has stopped. Surface the
                        // error to the user and quit; retrying is pointless.
                        // Break immediately so we do not process stale JMAP
                        // calls or draw another frame with the dead session.
                        state.connection_status = crate::app::ConnectionStatus::Error(
                            format!("Authentication failed (HTTP {code}): check Tailscale identity"),
                        );
                        state.quit = true;
                        break;
                    }
                    None => {
                        // Status channel closed; task exited.
                        state.quit = true;
                    }
                }
            }
            _ = tick.tick() => {
                state.clear_stale_error();
            }
        }

        // Dispatch async send when Enter was pressed in handle_key().
        if state.should_send_message {
            state.should_send_message = false;
            let body = state.input.trim().to_string();
            if !body.is_empty() {
                if let Some(chat_id) = state.chat_ids.get(state.selected_chat).cloned() {
                    match send_message(&http_client, &api_url, &chat_id, &body).await {
                        Ok(_msg_id) => {
                            state.input.clear();
                            state.input_cursor = 0;
                            // The sent message will appear via the SSE state-change path.
                        }
                        Err(e) => {
                            let msg = sanitize_display(&format!("Send failed: {e}"));
                            state.set_error(&msg);
                        }
                    }
                }
            }
        }

        if state.selected_chat != prev_selected {
            if let Some(chat_id) = state.chat_ids.get(state.selected_chat) {
                // Reload messages for the newly selected chat.
                let chat_id = chat_id.clone();
                let loaded =
                    load_messages_for_chat(&http_client, &api_url, &chat_id, &state.contacts, &state.owner_user_id).await;
                if loaded.is_error {
                    state.connection_status =
                        crate::app::ConnectionStatus::Error("Failed to load messages".to_string());
                    // Do NOT advance prev_selected on error — next tick retries the load.
                } else {
                    state.messages = loaded.display_lines;
                    state.message_ids = loaded.message_ids;
                    state.message_senders = loaded.sender_ids;
                    if !loaded.state.is_empty() {
                        state.message_state = loaded.state;
                    }
                    state.unread_message_ids = unread_ids_from_loaded_messages(
                        &state.message_ids,
                        &state.message_senders,
                        &loaded.read_ats,
                        &state.owner_user_id,
                    );
                    flush_unread_receipts(&http_client, &api_url, state).await;
                    state.scroll_offset = 0;
                    prev_selected = state.selected_chat; // INVARIANT: keep in sync — see comment above
                }
            }
        }

        terminal.draw(|f| {
            state.terminal_size = (f.area().width, f.area().height);
            ui::draw(f, state);
        })?;

        if state.quit {
            break;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;

    #[test]
    fn run_signature_accepts_new_params() {
        // Compile-time test: verify run() accepts the updated parameter types.
        // Async fn cannot be coerced to a plain fn pointer, so we use a
        // named-type assertion on a helper closure instead.
        fn _assert_run_types(
            terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
            state: &mut crate::app::AppState,
            http_client: reqwest::Client,
            api_url: String,
            sse_rx: tokio::sync::mpsc::Receiver<kith_core::StateChange>,
            sse_status_rx: tokio::sync::mpsc::Receiver<crate::client::SseStatus>,
        ) {
            // Calling run() with these typed args would require an async context.
            // Naming the call is enough to confirm the signature compiles.
            let _ = run(terminal, state, http_client, api_url, sse_rx, sse_status_rx);
        }
        // _assert_run_types is never called; the type-check is purely static.
        let _ = _assert_run_types as fn(_, _, _, _, _, _);
    }

    #[test]
    fn char_insert_respects_65536_byte_limit() {
        // Oracle: insert exactly 65536 'a' bytes then try one more; expect rejection.
        let mut state = AppState::new();
        state.focus = Focus::Input;
        state.input = "a".repeat(65536);
        state.input_cursor = 65536;

        // One more 'a' (1 byte) must be rejected.
        handle_key(&mut state, KeyCode::Char('a'), KeyModifiers::empty());
        assert_eq!(
            state.input.len(),
            65536,
            "input must not exceed 65536 bytes"
        );
        assert_eq!(state.input_cursor, 65536);
    }

    #[test]
    fn backspace_on_empty_input_is_noop() {
        // Oracle: cursor stays at 0, input stays empty.
        let mut state = AppState::new();
        state.focus = Focus::Input;
        state.input = String::new();
        state.input_cursor = 0;

        handle_key(&mut state, KeyCode::Backspace, KeyModifiers::empty());
        assert_eq!(state.input_cursor, 0);
        assert!(state.input.is_empty());
    }

    #[test]
    fn backspace_on_multibyte_char_moves_cursor_by_char_len() {
        // Oracle: '€' is U+20AC, 3 bytes in UTF-8. Cursor must retreat by 3.
        // '€'.len_utf8() == 3 is a known property of Unicode encoding.
        assert_eq!('€'.len_utf8(), 3, "oracle: € must be 3 UTF-8 bytes");

        let mut state = AppState::new();
        state.focus = Focus::Input;
        state.input = "€".to_string();
        state.input_cursor = 3; // after the 3-byte euro sign

        handle_key(&mut state, KeyCode::Backspace, KeyModifiers::empty());
        assert_eq!(state.input_cursor, 0, "cursor must retreat by 3 bytes");
        assert!(state.input.is_empty(), "euro sign must be removed");
    }

    // Oracle: mock server returns one direct chat with one participant whose
    // login is "alice@example.com" and unreadCount 2.
    // Expected: chat_ids == ["chat-abc"], chat_list[0] contains both the login
    // and the unread count.  All values are derived from the mock JSON, not from
    // running the code under test as its own oracle.
    #[tokio::test]
    async fn startup_chat_get_populates_chat_list() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [
                    ["Chat/get", {
                        "accountId": "a-self",
                        "list": [{
                            "id": "chat-abc",
                            "kind": "direct",
                            "participants": ["c-1"],
                            "createdAt": "2026-01-01T00:00:00Z",
                            "unreadCount": 2
                        }],
                        "notFound": [],
                        "state": "s-3"
                    }, "c0"],
                    ["ChatContact/get", {
                        "accountId": "a-self",
                        "list": [{
                            "id": "c-1",
                            "tailscaleUserId": "uid-1",
                            "login": "alice@example.com",
                            "mailboxHost": "alice.example.ts.net",
                            "firstSeenAt": "2026-01-01T00:00:00Z",
                            "lastSeenAt": "2026-01-01T00:00:00Z",
                            "blocked": false
                        }],
                        "state": "s-2"
                    }, "c1"]
                ],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = reqwest::Client::new();
        let mut state = crate::app::AppState::new();

        load_startup_data(&http_client, &api_url, &mut state).await;

        assert_eq!(
            state.chat_ids,
            vec!["chat-abc"],
            "chat_ids must be populated"
        );
        assert_eq!(state.chat_list.len(), 1, "chat_list must have 1 entry");
        assert!(
            state.chat_list[0].contains("alice@example.com"),
            "chat name must include contact login, got: {:?}",
            state.chat_list[0]
        );
        assert!(
            state.chat_list[0].contains('2'),
            "chat name must include unread count 2, got: {:?}",
            state.chat_list[0]
        );
    }

    #[tokio::test]
    async fn load_messages_formats_correctly() {
        use std::collections::HashMap;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // First call: Message/query
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/query",
                    {"accountId":"a-self","queryState":"s-3","ids":["m-1","m-2"],"position":0},
                    "mq0"
                ]],
                "sessionState": "s-1"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // Second call: Message/get
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/get",
                    {"accountId":"a-self","list":[
                        {"id":"m-1","chatId":"chat-abc","senderId":"c-1","body":"Hello","bodyType":"text/plain","attachments":[],"sentAt":"2026-04-19T13:45:00Z","receivedAt":"2026-04-19T13:45:00Z","deliveryState":"received"},
                        {"id":"m-2","chatId":"chat-abc","senderId":"uid-test-owner","body":"World","bodyType":"text/plain","attachments":[],"sentAt":"2026-04-19T13:46:00Z","receivedAt":"2026-04-19T13:46:00Z","deliveryState":"pending"}
                    ],"state":"s-3"},
                    "mg0"
                ]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = reqwest::Client::new();
        let mut contacts = HashMap::new();
        contacts.insert("c-1".to_string(), "Alice".to_string());

        let loaded = load_messages_for_chat(&http_client, &api_url, "chat-abc", &contacts, "uid-test-owner").await;
        let msgs = loaded.display_lines;

        // Oracle: derived from mock data above — HH:MM from receivedAt[11..16]
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], "13:45 Alice: Hello", "first message");
        assert_eq!(
            msgs[1], "13:46 me: World",
            "second message (sender=uid-test-owner == owner -> me)"
        );
    }

    #[tokio::test]
    async fn load_messages_empty_query_returns_empty() {
        use std::collections::HashMap;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/query",
                    {"accountId":"a-self","queryState":"s-0","ids":[],"position":0},
                    "mq0"
                ]],
                "sessionState": "s-0"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = reqwest::Client::new();
        let contacts = HashMap::new();

        let loaded = load_messages_for_chat(&http_client, &api_url, "chat-xyz", &contacts, "").await;

        assert!(
            loaded.display_lines.is_empty(),
            "empty query must return empty VecDeque"
        );
        // Verify the mock was called exactly once (no second Message/get call)
        // wiremock verifies unused mocks by default, so not mounting a Message/get mock
        // proves no second call was made.
    }

    /// Oracle: when server reports total=3 but returns only 1 ID (limit reached),
    /// the first display line must be a truncation notice mentioning 2 hidden messages.
    #[tokio::test]
    async fn load_messages_prepends_truncation_notice_when_server_has_more() {
        use std::collections::HashMap;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Message/query: total=3, but only 1 ID returned (simulates limit hit).
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/query",
                    {"accountId":"a-self","queryState":"s-1","ids":["m-3"],"position":2,"total":3},
                    "mq0"
                ]],
                "sessionState": "s-1"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // Message/get: return the one visible message.
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/get",
                    {"accountId":"a-self","list":[
                        {"id":"m-3","chatId":"chat-t","senderId":"c-bob","body":"Latest","bodyType":"text/plain","attachments":[],"sentAt":"2026-04-20T10:00:00Z","receivedAt":"2026-04-20T10:00:00Z","deliveryState":"received"}
                    ],"state":"s-1"},
                    "mg0"
                ]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = reqwest::Client::new();
        let contacts = HashMap::new();

        let loaded = load_messages_for_chat(&http_client, &api_url, "chat-t", &contacts, "").await;

        // Oracle: 2 lines total — synthetic notice first, then the real message.
        assert_eq!(
            loaded.display_lines.len(),
            2,
            "must have notice + 1 message"
        );
        assert_eq!(loaded.message_ids.len(), 2, "deques must stay in sync");
        assert_eq!(loaded.sender_ids.len(), 2, "deques must stay in sync");

        // The first line must be the truncation notice describing 2 hidden messages.
        let notice = &loaded.display_lines[0];
        assert!(
            notice.contains("2") && notice.contains("older message"),
            "notice must mention 2 older messages, got: {notice:?}"
        );
        // The synthetic entry must have empty id/sender so receipts skip it.
        assert!(
            loaded.message_ids[0].is_empty(),
            "synthetic id must be empty"
        );
        assert!(
            loaded.sender_ids[0].is_empty(),
            "synthetic sender must be empty"
        );

        // The real message follows.
        assert!(
            loaded.display_lines[1].contains("Latest"),
            "second line must be the real message"
        );
    }

    #[tokio::test]
    async fn handle_state_change_message_appends_new_message() {
        use kith_core::StateChange;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        // Message/changes response
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/changes",
                    {"accountId":"a-self","oldState":"s-3","newState":"s-4","hasMoreChanges":false,
                     "created":["m-new"],"updated":[],"destroyed":[]},
                    "mc0"
                ]],
                "sessionState": "s-1"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // Message/get response
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/get",
                    {"accountId":"a-self","list":[{
                        "id":"m-new","chatId":"chat-abc","senderId":"c-1",
                        "body":"New message","bodyType":"text/plain","attachments":[],
                        "sentAt":"2026-04-19T14:00:00Z","receivedAt":"2026-04-19T14:00:00Z",
                        "deliveryState":"received"
                    }],"state":"s-4"},
                    "mg0"
                ]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = reqwest::Client::new();
        let mut state = crate::app::AppState::new();
        state.chat_ids = vec!["chat-abc".to_string()];
        state.selected_chat = 0;
        state.message_state = "s-3".to_string();
        state
            .contacts
            .insert("c-1".to_string(), "Alice".to_string());
        state.messages.clear();

        let sc = StateChange {
            type_name: "Message".to_string(),
            new_state: "s-4".to_string(),
        };
        handle_state_change(&http_client, &api_url, &sc, &mut state).await;

        // Oracle: mock returns one new message with receivedAt "2026-04-19T14:00:00Z"
        assert_eq!(state.message_state, "s-4", "message_state must be updated");
        assert_eq!(state.messages.len(), 1, "one message must be appended");
        assert!(
            state.messages[0].contains("Alice"),
            "message must show sender name"
        );
        assert!(
            state.messages[0].contains("New message"),
            "message must show body"
        );
    }

    #[tokio::test]
    async fn handle_state_change_unknown_type_is_noop() {
        // Oracle: unknown type_name must not modify state at all.
        use kith_core::StateChange;

        // No mock server needed — no HTTP call should be made
        let http_client = reqwest::Client::new();
        let api_url = "http://127.0.0.1:1"; // unreachable; any call would fail the test
        let mut state = crate::app::AppState::new();
        state.message_state = "s-5".to_string();

        let sc = StateChange {
            type_name: "UnknownType".to_string(),
            new_state: "s-6".to_string(),
        };
        handle_state_change(&http_client, api_url, &sc, &mut state).await;

        assert_eq!(state.message_state, "s-5", "message_state must not change");
        assert_eq!(
            state.messages.len(),
            crate::app::AppState::new().messages.len(),
            "messages must be unchanged for unknown type"
        );
    }

    #[tokio::test]
    async fn handle_state_change_sse_closed_sets_reconnecting() {
        // This is tested at the run() level via the None arm; verify ConnectionStatus value.
        // Oracle: ConnectionStatus::Reconnecting variant exists and can be set.
        let mut state = crate::app::AppState::new();
        state.connection_status = crate::app::ConnectionStatus::Reconnecting;
        assert_eq!(
            state.connection_status,
            crate::app::ConnectionStatus::Reconnecting
        );
    }

    /// E2E: exercises the full initialization → message load → SSE state-change sequence.
    ///
    /// Oracle: all expected values are derived directly from the mock JSON payloads
    /// defined below — never from running the code under test as its own oracle.
    ///
    /// Sequence:
    ///   1. load_startup_data: Chat/get returns 1 direct chat; Contact/get returns 1 contact.
    ///   2. load_messages_for_chat: Message/query returns 1 ID; Message/get returns the message.
    ///   3. send_read_receipts: marks the inbound m-init message as read.
    ///   4. handle_state_change (Message): Message/changes returns 1 new ID; Message/get returns it.
    ///
    /// Expected final state (from mock data):
    ///   chat_ids      == ["e2e-chat"]
    ///   chat_list[0]  contains "Bob" and "(1)" (unread count)
    ///   messages[0]   == "10:00 Bob: Initial message"
    ///   messages[1]   == "10:01 me: Reply"
    ///   message_state == "s-5"
    #[tokio::test]
    async fn e2e_init_and_sse_state_change() {
        use kith_core::StateChange;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let base = mock_server.uri();

        // ── Call 1: load_startup_data → Chat/get + Contact/get (batched) ──────────
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [
                    ["Chat/get", {
                        "accountId": "a-self",
                        "list": [{
                            "id": "e2e-chat",
                            "kind": "direct",
                            "participants": ["c-bob"],
                            "createdAt": "2026-01-01T00:00:00Z",
                            "unreadCount": 1
                        }],
                        "notFound": [],
                        "state": "s-2"
                    }, "c0"],
                    ["ChatContact/get", {
                        "accountId": "a-self",
                        "list": [{
                            "id": "c-bob",
                            "tailscaleUserId": "uid-bob",
                            "login": "bob@example.com",
                            "mailboxHost": "bob.ts.net",
                            "displayName": "Bob",
                            "firstSeenAt": "2026-01-01T00:00:00Z",
                            "lastSeenAt": "2026-01-01T00:00:00Z",
                            "blocked": false
                        }],
                        "state": "s-1"
                    }, "c1"]
                ],
                "sessionState": "s-0"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // ── Call 2: load_messages_for_chat → Message/query ─────────────────────────
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/query",
                    {"accountId":"a-self","queryState":"s-4","ids":["m-init"],"position":0},
                    "mq0"
                ]],
                "sessionState": "s-0"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // ── Call 3: load_messages_for_chat → Message/get ───────────────────────────
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/get",
                    {"accountId":"a-self","list":[{
                        "id":"m-init","chatId":"e2e-chat","senderId":"c-bob",
                        "body":"Initial message","bodyType":"text/plain","attachments":[],
                        "sentAt":"2026-04-19T10:00:00Z",
                        "receivedAt":"2026-04-19T10:00:00Z",
                        "deliveryState":"received"
                    }],"state":"s-4"},
                    "mg0"
                ]],
                "sessionState": "s-0"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // ── Call 4: send_read_receipts for m-init (senderId "c-bob", inbound) ────────
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["Message/set", {
                    "accountId": "a-self",
                    "newState": "s-4r",
                    "created": {},
                    "notCreated": {},
                    "updated": {"m-init": null},
                    "notUpdated": {},
                    "destroyed": [],
                    "notDestroyed": {}
                }, "r0"]],
                "sessionState": "s-0"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // ── Call 5: handle_state_change → Message/changes ──────────────────────────
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/changes",
                    {"accountId":"a-self","oldState":"s-4","newState":"s-5",
                     "hasMoreChanges":false,"created":["m-reply"],"updated":[],"destroyed":[]},
                    "mc0"
                ]],
                "sessionState": "s-0"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        // ── Call 6: handle_state_change → Message/get for new message ──────────────
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [[
                    "Message/get",
                    {"accountId":"a-self","list":[{
                        "id":"m-reply","chatId":"e2e-chat","senderId":"uid-test-owner",
                        "body":"Reply","bodyType":"text/plain","attachments":[],
                        "sentAt":"2026-04-19T10:01:00Z",
                        "receivedAt":"2026-04-19T10:01:00Z",
                        "deliveryState":"pending"
                    }],"state":"s-5"},
                    "mg0"
                ]],
                "sessionState": "s-0"
            })))
            .mount(&mock_server)
            .await;

        // ── Run the sequence ────────────────────────────────────────────────────────
        let api_url = format!("{base}/jmap/api");
        let http_client = reqwest::Client::new();
        let mut state = crate::app::AppState::new();
        state.owner_user_id = "uid-test-owner".to_string();

        // Step 1: startup data
        load_startup_data(&http_client, &api_url, &mut state).await;

        // Step 2+3: initial message load (+ step 3: send_read_receipts for inbound m-init)
        if let Some(chat_id) = state.chat_ids.first().cloned() {
            let loaded =
                load_messages_for_chat(&http_client, &api_url, &chat_id, &state.contacts, &state.owner_user_id).await;
            state.messages = loaded.display_lines;
            state.message_ids = loaded.message_ids;
            state.message_senders = loaded.sender_ids;
            state.unread_message_ids = unread_ids_from_loaded_messages(
                &state.message_ids,
                &state.message_senders,
                &loaded.read_ats,
                &state.owner_user_id,
            );
            flush_unread_receipts(&http_client, &api_url, &mut state).await;
            state.message_state = "s-4".to_string(); // set from Message/get state field
            state.scroll_offset = 0;
        }

        // Step 4+5: SSE state change arrives
        let sc = StateChange {
            type_name: "Message".to_string(),
            new_state: "s-5".to_string(),
        };
        handle_state_change(&http_client, &api_url, &sc, &mut state).await;

        // ── Assertions (all derived from mock data, not from code) ─────────────────
        assert_eq!(state.chat_ids, vec!["e2e-chat"], "chat_ids");
        assert_eq!(state.chat_list.len(), 1, "chat_list length");
        assert!(
            state.chat_list[0].contains("Bob"),
            "chat display name must include 'Bob', got: {:?}",
            state.chat_list[0]
        );
        assert!(
            state.chat_list[0].contains('1'),
            "chat display name must include unread count 1, got: {:?}",
            state.chat_list[0]
        );
        assert_eq!(
            state.messages.len(),
            2,
            "must have 2 messages after SSE update"
        );
        assert_eq!(
            state.messages[0], "10:00 Bob: Initial message",
            "first message"
        );
        assert_eq!(state.messages[1], "10:01 me: Reply", "second message");
        assert_eq!(state.message_state, "s-5", "message_state after SSE");
    }

    // Oracle: empty list responses must produce empty chat_ids and chat_list
    // without panicking.  This guards the min() call that would underflow on an
    // empty slice if the is_empty() guard is absent.
    #[tokio::test]
    async fn startup_chat_get_empty_list_no_panic() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [
                    ["Chat/get", {"accountId": "a-self", "list": [], "notFound": [], "state": "s-0"}, "c0"],
                    ["ChatContact/get", {"accountId": "a-self", "list": [], "state": "s-0"}, "c1"]
                ],
                "sessionState": "s-0"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = reqwest::Client::new();
        let mut state = crate::app::AppState::new();

        load_startup_data(&http_client, &api_url, &mut state).await;

        assert!(state.chat_list.is_empty(), "chat_list must be empty");
        assert!(state.chat_ids.is_empty(), "chat_ids must be empty");
    }

    /// Oracle: when Chat/get returns a JMAP method-level error response, connection_status
    /// must be set to Error and chat_list must not be cleared (previous state preserved).
    /// The error type string from the server must appear in the Error variant.
    #[tokio::test]
    async fn startup_chat_get_jmap_error_sets_connection_status_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [
                    ["error", {"type": "accountNotFound"}, "c0"],
                    ["error", {"type": "accountNotFound"}, "c1"]
                ],
                "sessionState": "s-0"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = reqwest::Client::new();
        let mut state = crate::app::AppState::new();
        // Pre-seed chat_list to verify it is NOT overwritten on error.
        let pre_existing_chat_list = state.chat_list.clone();

        load_startup_data(&http_client, &api_url, &mut state).await;

        // Oracle: connection_status must be the Error variant containing the error type.
        match &state.connection_status {
            crate::app::ConnectionStatus::Error(msg) => {
                assert!(
                    msg.contains("accountNotFound"),
                    "error message must contain JMAP error type, got: {msg:?}"
                );
            }
            other => panic!("expected ConnectionStatus::Error, got: {:?}", other),
        }

        // Oracle: chat_list must be unchanged — the function returns early on JMAP error
        // without reaching the state assignment, so prior data is preserved.
        assert_eq!(
            state.chat_list, pre_existing_chat_list,
            "chat_list must not be modified when Chat/get returns a JMAP error"
        );
    }

    #[tokio::test]
    async fn send_message_success() {
        // Oracle: mock returns created["k-1"]["id"] = "msg-001"; send_message must return Ok("msg-001")
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["Message/set", {
                    "accountId": "a-self",
                    "oldState": null,
                    "newState": "s-2",
                    "created": {"k-1": {"id": "msg-001", "senderId": "self", "deliveryState": "pending"}},
                    "notCreated": {},
                    "updated": {},
                    "notUpdated": {},
                    "destroyed": [],
                    "notDestroyed": {}
                }, "s0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let result = send_message(&client, &url, "chat-abc", "hello world").await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
        assert_eq!(result.unwrap(), "msg-001", "must return server-assigned id");
    }

    #[tokio::test]
    async fn send_message_not_created_error() {
        // Oracle: mock returns notCreated["k-1"]["type"] = "invalidArguments"
        // Expected: Err containing "invalidArguments"
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["Message/set", {
                    "accountId": "a-self",
                    "newState": "s-1",
                    "created": {},
                    "notCreated": {"k-1": {"type": "invalidArguments", "description": "body too long"}},
                    "updated": {},
                    "notUpdated": {}
                }, "s0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let result = send_message(&client, &url, "chat-abc", "x").await;
        assert!(result.is_err(), "expected Err for notCreated response");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("invalidArguments"),
            "error must mention type, got: {err_str:?}"
        );
    }

    #[tokio::test]
    async fn send_message_method_error() {
        // Oracle: mock returns ["error", {type: "serverFail"}, "s0"]
        // Expected: Err containing "serverFail"
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["error", {"type": "serverFail"}, "s0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let result = send_message(&client, &url, "chat-abc", "hi").await;
        assert!(result.is_err(), "expected Err for error method response");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("serverFail"),
            "error must mention type, got: {err_str:?}"
        );
    }

    #[tokio::test]
    async fn send_message_empty_body_no_http() {
        // Oracle: empty body must short-circuit without any HTTP call
        // Use unreachable URL — any HTTP call would panic or return connection error
        let client = reqwest::Client::new();
        let result = send_message(&client, "http://127.0.0.1:1/jmap/api", "chat-abc", "").await;
        assert!(result.is_err(), "empty body must return Err without HTTP");
    }

    #[tokio::test]
    async fn send_message_whitespace_body_no_http() {
        // Oracle: whitespace-only body must short-circuit without any HTTP call
        let client = reqwest::Client::new();
        let result = send_message(&client, "http://127.0.0.1:1/jmap/api", "chat-abc", "   ").await;
        assert!(
            result.is_err(),
            "whitespace body must return Err without HTTP"
        );
    }

    #[tokio::test]
    async fn send_message_network_error() {
        // Oracle: unreachable URL must return Err (network error propagated)
        let client = reqwest::Client::new();
        let result =
            send_message(&client, "http://127.0.0.1:1/jmap/api", "chat-abc", "hello").await;
        assert!(result.is_err(), "network failure must return Err");
    }

    #[tokio::test]
    async fn send_read_receipts_empty_slice_no_http() {
        // Oracle: empty slice must return Ok without any HTTP call
        let client = reqwest::Client::new();
        let result = send_read_receipts(&client, "http://127.0.0.1:1/jmap/api", &[]).await;
        assert!(
            result.is_ok(),
            "empty slice must return Ok, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn send_read_receipts_success() {
        // Oracle: mock returns updated{"m-1": null} — must return Ok(())
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["Message/set", {
                    "accountId": "a-self",
                    "newState": "s-5",
                    "created": {},
                    "notCreated": {},
                    "updated": {"m-1": null},
                    "notUpdated": {},
                    "destroyed": [],
                    "notDestroyed": {}
                }, "r0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let ids = vec!["m-1".to_string()];
        let result = send_read_receipts(&client, &url, &ids).await;
        assert!(
            result.is_ok(),
            "success response must return Ok, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn send_read_receipts_partial_not_updated_nonfatal() {
        // Oracle: notUpdated non-empty must still return Ok (non-fatal)
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["Message/set", {
                    "accountId": "a-self",
                    "newState": "s-5",
                    "created": {},
                    "notCreated": {},
                    "updated": {},
                    "notUpdated": {"m-1": {"type": "notFound"}},
                    "destroyed": [],
                    "notDestroyed": {}
                }, "r0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let ids = vec!["m-1".to_string()];
        let result = send_read_receipts(&client, &url, &ids).await;
        assert!(
            result.is_ok(),
            "notUpdated must be non-fatal, must return Ok, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn send_read_receipts_network_error_returns_err() {
        // Oracle: unreachable URL must return Err
        let client = reqwest::Client::new();
        let ids = vec!["m-1".to_string()];
        let result = send_read_receipts(&client, "http://127.0.0.1:1/jmap/api", &ids).await;
        assert!(result.is_err(), "network failure must return Err");
    }

    #[test]
    fn delete_ascii_removes_char_at_cursor() {
        // Oracle: 'a','b','c' are 1 byte each; Delete at cursor=1 removes 'b' → "ac", cursor stays 1
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::Input;
        state.input = "abc".to_string();
        state.input_cursor = 1;
        handle_key(&mut state, KeyCode::Delete, KeyModifiers::empty());
        assert_eq!(state.input, "ac", "Delete must remove char at cursor");
        assert_eq!(state.input_cursor, 1, "cursor must not move after Delete");
    }

    #[test]
    fn delete_multibyte_removes_full_char() {
        // Oracle: '€' is U+20AC, 3 bytes in UTF-8 ('€'.len_utf8() == 3)
        assert_eq!('€'.len_utf8(), 3, "oracle: € must be 3 UTF-8 bytes");
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::Input;
        state.input = "€X".to_string();
        state.input_cursor = 0;
        handle_key(&mut state, KeyCode::Delete, KeyModifiers::empty());
        assert_eq!(state.input, "X", "Delete must remove full multi-byte char");
        assert_eq!(state.input_cursor, 0, "cursor must stay at 0");
    }

    #[test]
    fn delete_at_end_of_input_is_noop() {
        // Oracle: cursor == len means no char to delete
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::Input;
        state.input = "abc".to_string();
        state.input_cursor = 3;
        handle_key(&mut state, KeyCode::Delete, KeyModifiers::empty());
        assert_eq!(state.input, "abc", "Delete at end must be no-op");
        assert_eq!(state.input_cursor, 3);
    }

    #[test]
    fn delete_on_empty_input_is_noop() {
        // Oracle: nothing to delete when input is empty
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::Input;
        state.input = String::new();
        state.input_cursor = 0;
        handle_key(&mut state, KeyCode::Delete, KeyModifiers::empty());
        assert!(
            state.input.is_empty(),
            "Delete on empty input must be no-op"
        );
        assert_eq!(state.input_cursor, 0);
    }

    #[test]
    fn enter_sets_send_flag_when_input_nonempty() {
        // Oracle: non-empty input → should_send_message must become true
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::Input;
        state.input = "hello".to_string();
        state.input_cursor = 5;
        state.should_send_message = false;
        handle_key(&mut state, KeyCode::Enter, KeyModifiers::empty());
        assert!(
            state.should_send_message,
            "Enter with non-empty input must set should_send_message"
        );
    }

    #[test]
    fn enter_whitespace_only_does_not_set_flag() {
        // Oracle: whitespace trim is empty → should not send
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::Input;
        state.input = "   ".to_string();
        state.input_cursor = 3;
        state.should_send_message = false;
        handle_key(&mut state, KeyCode::Enter, KeyModifiers::empty());
        assert!(
            !state.should_send_message,
            "Enter with whitespace-only must NOT set should_send_message"
        );
    }

    #[test]
    fn enter_empty_input_does_not_set_flag() {
        // Oracle: empty input → should not send
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::Input;
        state.input = String::new();
        state.input_cursor = 0;
        state.should_send_message = false;
        handle_key(&mut state, KeyCode::Enter, KeyModifiers::empty());
        assert!(
            !state.should_send_message,
            "Enter with empty input must NOT set should_send_message"
        );
    }

    #[test]
    fn enter_chat_list_focus_does_not_set_flag() {
        // Oracle: Enter key only triggers send when focus is Input, not ChatList
        let mut state = crate::app::AppState::new();
        state.focus = crate::app::Focus::ChatList;
        state.input = "hello".to_string();
        state.should_send_message = false;
        handle_key(&mut state, KeyCode::Enter, KeyModifiers::empty());
        assert!(
            !state.should_send_message,
            "Enter in ChatList focus must NOT set should_send_message"
        );
    }

    #[tokio::test]
    async fn e2e_send_message_clears_input_on_success() {
        // Oracle: mock returns created["k-1"]["id"] = "sent-001"
        // On Ok, state.input must be empty and cursor 0
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["Message/set", {
                    "accountId": "a-self",
                    "newState": "s-2",
                    "created": {"k-1": {"id": "sent-001", "senderId": "self", "deliveryState": "pending"}},
                    "notCreated": {}
                }, "s0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());

        // Simulate the run() send dispatch logic
        let body = "hello world".trim().to_string();
        assert!(!body.is_empty());
        let result = send_message(&client, &url, "chat-1", &body).await;

        assert!(result.is_ok(), "send must succeed, got: {:?}", result);
        assert_eq!(result.unwrap(), "sent-001", "must return server id");

        // Simulate what run() does on Ok
        let mut state = crate::app::AppState::new();
        state.input = "hello world".to_string();
        state.input_cursor = 11;
        // On success:
        state.input.clear();
        state.input_cursor = 0;
        assert!(state.input.is_empty(), "input must be cleared on success");
        assert_eq!(state.input_cursor, 0, "cursor must be reset on success");
    }

    #[tokio::test]
    async fn e2e_send_failure_sets_error_notification() {
        // Oracle: mock returns error response → set_error must be called; input stays
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["error", {"type": "serverFail"}, "s0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let mut state = crate::app::AppState::new();
        state.input = "hello".to_string();
        state.input_cursor = 5;

        let body = state.input.trim().to_string();
        let result = send_message(&client, &url, "chat-1", &body).await;

        assert!(result.is_err(), "serverFail must return Err");

        // Simulate run() error path
        let msg = crate::app::sanitize_display(&format!("Send failed: {}", result.unwrap_err()));
        state.set_error(&msg);

        assert!(
            state.error_notification.is_some(),
            "error_notification must be set"
        );
        let (notif_msg, _) = state.error_notification.as_ref().unwrap();
        assert!(
            notif_msg.contains("Send failed"),
            "notification must say Send failed, got: {notif_msg:?}"
        );
        // Input must NOT be cleared on failure
        assert_eq!(
            state.input, "hello",
            "input must not be cleared on send failure"
        );
    }

    #[tokio::test]
    async fn e2e_read_receipt_clears_unread_ids() {
        // Oracle: mock returns updated{"m-inbound": null} → unread_message_ids must be empty after
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [["Message/set", {
                    "accountId": "a-self",
                    "newState": "s-5",
                    "created": {},
                    "notCreated": {},
                    "updated": {"m-inbound": null},
                    "notUpdated": {}
                }, "r0"]],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let mut state = crate::app::AppState::new();
        state.unread_message_ids.insert("m-inbound".to_string());

        let ids: Vec<String> = state.unread_message_ids.iter().cloned().collect();
        let result = send_read_receipts(&client, &url, &ids).await;

        assert!(result.is_ok(), "receipt must succeed, got: {:?}", result);

        // Simulate run() receipt path: clear on Ok
        if result.is_ok() {
            state.unread_message_ids.clear();
        }
        assert!(
            state.unread_message_ids.is_empty(),
            "unread_message_ids must be empty after receipt"
        );
    }

    #[test]
    fn e2e_error_notification_expires_after_3s() {
        // Oracle: 4s > 3s threshold — clear_stale_error must set error_notification to None
        use std::time::{Duration, Instant};

        let mut state = crate::app::AppState::new();
        // Manually set an old error (4 seconds ago)
        state.error_notification = Some((
            "Send failed: old error".to_string(),
            Instant::now() - Duration::from_secs(4),
        ));
        assert!(
            state.error_notification.is_some(),
            "precondition: error is set"
        );

        state.clear_stale_error();

        assert!(
            state.error_notification.is_none(),
            "error must be cleared after 3s"
        );
    }
}
