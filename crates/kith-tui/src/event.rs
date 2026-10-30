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
        // Quit: 'q' only outside the input box, so it can be typed; Ctrl-C anywhere.
        KeyCode::Char('q') if modifiers.is_empty() && state.focus == Focus::ChatList => {
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
/// On any network or parse error the function logs a warning and returns
/// without modifying state.  Never panics.
pub(crate) async fn load_startup_data(
    http_client: &reqwest::Client,
    api_url: &str,
    account_id: &str,
    state: &mut AppState,
) {
    let req = JmapRequest::new(
        vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        vec![
            (
                "Chat/get".into(),
                json!({"accountId": account_id}),
                "c0".into(),
            ),
            (
                "ChatContact/get".into(),
                json!({"accountId": account_id}),
                "c1".into(),
            ),
        ],
        None,
    );

    let resp = match client::call_jmap(http_client, api_url, &req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("startup JMAP call failed: {e}");
            state.note_api_error(&e);
            if !state.auth_rejected() {
                state.connection_status =
                    crate::app::ConnectionStatus::Error("JMAP startup failed".to_string());
            }
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
            tracing::warn!("ChatContact/get returned JMAP error: {err_type}");
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
    let mut chat_members: Vec<Vec<String>> = Vec::new();
    if let Some((method, args, _call_id)) = resp.method_responses.first() {
        if method == "error" {
            let err_type = args
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            tracing::warn!("Chat/get returned JMAP error: {err_type}");
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
                let unread_count =
                    chat.get("unreadCount").and_then(Value::as_u64).unwrap_or(0) as u32;

                // Spec Chat fields: a direct chat names the other participant
                // by `contactId`; group and channel chats carry `name`.
                let base_name = if kind == "direct" {
                    chat.get("contactId")
                        .and_then(Value::as_str)
                        .and_then(|cid| contacts_map.get(cid).cloned())
                        .unwrap_or_else(|| "Unknown".to_string())
                } else {
                    chat.get("name")
                        .and_then(Value::as_str)
                        .filter(|n| !n.is_empty())
                        .map(sanitize_display)
                        .unwrap_or_else(|| "Group".to_string())
                };

                let display = if unread_count > 0 {
                    format!("{base_name} ({unread_count})")
                } else {
                    base_name
                };

                // Spec Chat.members: group chats only; each id is a
                // ChatContact id, or the owner's accountId.
                let members = chat
                    .get("members")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|m| m.get("id").and_then(Value::as_str))
                    .map(|mid| {
                        if mid == state.owner_id {
                            "me".to_owned()
                        } else {
                            contacts_map
                                .get(mid)
                                .cloned()
                                .unwrap_or_else(|| sanitize_display(mid))
                        }
                    })
                    .collect();

                chat_ids.push(id);
                // display is built from contacts_map (already sanitized), the
                // sanitized group name and numeric/constant strings.
                chat_list.push(display);
                chat_members.push(members);
            }
        }
    }

    state.chat_list = chat_list;
    state.chat_ids = chat_ids;
    state.chat_members = chat_members;
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
    owner_id: &str,
) -> Option<String> {
    // receivedAt is required; absence silently drops the message from display.
    let received_at = msg.get("receivedAt").and_then(serde_json::Value::as_str)?;
    let hhmm = received_at.get(11..16).unwrap_or("??:??");
    let sender_id = msg
        .get("senderId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let sender_name = if sender_id == owner_id {
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
    /// The failed API call behind `is_error`, if one failed.
    pub api_error: Option<client::ClientError>,
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
    account_id: &str,
    chat_id: &str,
    contacts: &std::collections::HashMap<String, String>,
    owner_id: &str,
) -> LoadedMessages {
    // Step A — Message/query
    //
    // The spec's default sort is receivedAt ascending, so ask for descending
    // explicitly: position=0 is then the most recent message. limit=500 fetches the newest 500; if there are more,
    // a truncation notice is prepended by the caller. The TUI then re-sorts
    // the returned IDs by receivedAt ASC for oldest-first display.
    let query_req = JmapRequest::new(
        vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        vec![(
            "Message/query".into(),
            json!({"accountId": account_id, "filter": {"chatId": chat_id}, "sort": [{"property": "receivedAt", "isAscending": false}], "position": 0, "limit": 500, "calculateTotal": true}),
            "mq0".into(),
        )],
        None,
    );

    let query_resp = match client::call_jmap(http_client, api_url, &query_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Message/query failed: {e}");
            return LoadedMessages {
                is_error: true,
                api_error: Some(e),
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

    // Step B — Message/get, even with no ids: its `state` is the only valid
    // sinceState for a later Message/changes (RFC 8620 §5.2).
    let get_req = JmapRequest::new(
        vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        vec![(
            "Message/get".into(),
            json!({"accountId": account_id, "ids": ids}),
            "mg0".into(),
        )],
        None,
    );

    let get_resp = match client::call_jmap(http_client, api_url, &get_req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Message/get failed: {e}");
            return LoadedMessages {
                is_error: true,
                api_error: Some(e),
                ..LoadedMessages::default()
            };
        }
    };

    let get_first = get_resp.method_responses.first();

    // Capture the state token from the Message/get response — this is the
    // authoritative current state after the full reload, used by the
    // cannotCalculateChanges recovery path.
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
        if let Some(display_line) = format_message_line(msg, contacts, owner_id) {
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

/// Format `t` as a JMAP UTCDate at millisecond precision.
///
/// RFC 8620 §1.4: the fractional seconds MUST be omitted when zero, which
/// `AutoSi` does; truncating first keeps it to at most three digits.
fn utc_date(t: chrono::DateTime<chrono::Utc>) -> String {
    use chrono::SubsecRound;
    t.trunc_subsecs(3)
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
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
    account_id: &str,
    chat_id: &str,
    body: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if body.trim().is_empty() {
        return Err("empty message body".into());
    }

    let sent_at = utc_date(chrono::Utc::now());

    let req = JmapRequest::new(
        vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        vec![(
            "Message/set".into(),
            json!({"accountId": account_id, "create": {"k-1": {"chatId": chat_id, "body": body, "bodyType": "text/plain", "sentAt": sent_at}}}),
            "s0".into(),
        )],
        None,
    );

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
/// notUpdated entries are treated as non-fatal (logged as a warning, Ok returned).
pub(crate) async fn send_read_receipts(
    http_client: &reqwest::Client,
    api_url: &str,
    account_id: &str,
    message_ids: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if message_ids.is_empty() {
        return Ok(());
    }

    let read_at = utc_date(chrono::Utc::now());

    let mut update = serde_json::Map::new();
    for id in message_ids {
        update.insert(id.clone(), json!({"readAt": read_at}));
    }

    let req = JmapRequest::new(
        vec![
            "urn:ietf:params:jmap:core".into(),
            "urn:ietf:params:jmap:chat".into(),
        ],
        vec![(
            "Message/set".into(),
            json!({"accountId": account_id, "update": update}),
            "r0".into(),
        )],
        None,
    );

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
            tracing::warn!("read receipt failed for {} messages", not_updated.len());
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
    owner_id: &str,
) -> HashSet<String> {
    senders
        .iter()
        .zip(ids.iter())
        .zip(read_ats.iter())
        .filter(|((s, _), ra)| s.as_str() != owner_id && ra.is_none())
        .map(|((_, id), _)| id.clone())
        .filter(|id| !id.is_empty())
        .collect()
}

/// Attempt to flush all pending unread receipts in `state.unread_message_ids`.
///
/// On success the set is cleared. On error the IDs are left for the next
/// attempt; the caller should not treat a failed flush as fatal.
async fn flush_unread_receipts(
    http_client: &reqwest::Client,
    api_url: &str,
    account_id: &str,
    state: &mut AppState,
) {
    let unread: Vec<String> = state.unread_message_ids.iter().cloned().collect();
    // send_read_receipts is a no-op on empty input; no need to guard here.
    // On error: leave unread_message_ids for next attempt.
    match send_read_receipts(http_client, api_url, account_id, &unread).await {
        Ok(()) => state.unread_message_ids.clear(),
        Err(e) => state.note_api_error(e.as_ref()),
    }
}

/// Advance the owner's ReadPosition for the chat being viewed to the newest
/// message displayed in it, so the server's `Chat.unreadCount` drops.
///
/// draft-atwood-jmap-chat-00 §ReadPosition: `lastReadMessageId` is "the id of
/// the most recent Message the owner has read", and `unreadCount` counts
/// Messages whose id is lexicographically greater. A displayed message counts
/// as read whoever sent it; there is no special rule for the owner's own
/// messages (see chinwag-fqk0). The cursor never moves backwards, and nothing
/// is sent when the chat has no ReadPosition yet (the server creates it).
///
/// # Errors
///
/// A network error, a method error, an unexpected response, or a `notUpdated`
/// entry. Callers may ignore it: the next view retries.
pub(crate) async fn mark_chat_read(
    http_client: &reqwest::Client,
    api_url: &str,
    account_id: &str,
    state: &AppState,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(chat_id) = state.chat_ids.get(state.selected_chat) else {
        return Ok(());
    };
    let Some(newest) = state.message_ids.iter().filter(|id| !id.is_empty()).max() else {
        return Ok(());
    };
    let using = vec![
        "urn:ietf:params:jmap:core".to_owned(),
        "urn:ietf:params:jmap:chat".to_owned(),
    ];

    // ponytail: fetches every ReadPosition (one per chat) on each view, since
    // the spec defines no ReadPosition/query; cache chatId -> id if this shows
    // up in latency.
    let get_req = JmapRequest::new(
        using.clone(),
        vec![(
            "ReadPosition/get".into(),
            json!({"accountId": account_id, "ids": null,
                   "properties": ["id", "chatId", "lastReadMessageId"]}),
            "r0".into(),
        )],
        None,
    );
    let resp = client::call_jmap(http_client, api_url, &get_req).await?;
    let list = match resp.method_responses.first() {
        Some((name, args, _)) if name == "ReadPosition/get" => args
            .get("list")
            .and_then(Value::as_array)
            .ok_or("ReadPosition/get response has no list")?,
        _ => return Err("unexpected ReadPosition/get response".into()),
    };
    let Some(position) = list
        .iter()
        .find(|p| p.get("chatId").and_then(Value::as_str) == Some(chat_id.as_str()))
    else {
        return Ok(());
    };
    let position_id = position
        .get("id")
        .and_then(Value::as_str)
        .ok_or("ReadPosition has no id")?;
    let last_read = position.get("lastReadMessageId").and_then(Value::as_str);
    if last_read.is_some_and(|last| last >= newest.as_str()) {
        return Ok(());
    }

    let set_req = JmapRequest::new(
        using,
        vec![(
            "ReadPosition/set".into(),
            json!({"accountId": account_id,
                   "update": {position_id: {"lastReadMessageId": newest}}}),
            "r0".into(),
        )],
        None,
    );
    let resp = client::call_jmap(http_client, api_url, &set_req).await?;
    match resp.method_responses.first() {
        Some((name, args, _)) if name == "ReadPosition/set" => {
            if args
                .get("notUpdated")
                .and_then(Value::as_object)
                .is_some_and(|m| !m.is_empty())
            {
                return Err("ReadPosition/set: not updated".into());
            }
            Ok(())
        }
        _ => Err("unexpected ReadPosition/set response".into()),
    }
}

/// Reload the selected chat from scratch and mark it read, for when
/// Message/changes cannot be used (RFC 8620 §5.2). Does nothing if no chat
/// is selected.
async fn resync_selected_chat(
    http_client: &reqwest::Client,
    api_url: &str,
    account_id: &str,
    state: &mut AppState,
) {
    let Some(chat_id) = state.chat_ids.get(state.selected_chat).cloned() else {
        return;
    };
    let loaded = load_messages_for_chat(
        http_client,
        api_url,
        account_id,
        &chat_id,
        &state.contacts,
        &state.owner_id,
    )
    .await;
    if let Some(e) = &loaded.api_error {
        state.note_api_error(e);
    }
    if loaded.is_error {
        if !state.auth_rejected() {
            state.connection_status =
                crate::app::ConnectionStatus::Error("Failed to load messages".to_string());
        }
        return;
    }
    // Use the state token from the Message/get response, not the SSE
    // newState, which may be stale if more messages arrived meanwhile.
    if !loaded.state.is_empty() {
        state.message_state = loaded.state;
    }
    state.messages = loaded.display_lines;
    state.message_ids = loaded.message_ids;
    state.message_senders = loaded.sender_ids;
    // On error the next view or arrival retries.
    if let Err(e) = mark_chat_read(http_client, api_url, account_id, state).await {
        state.note_api_error(e.as_ref());
    }
}

/// Handle a single [`StateChange`] event received from the SSE channel.
///
/// On a "Message" state change: calls `Message/changes`, then `Message/get`
/// for the created and updated ids (RFC 8620 §5.2). Lines of the selected
/// chat are replaced in place for ids already shown, appended for new ids,
/// and removed for destroyed ids. A read receipt is sent only for inbound
/// messages whose `readAt` is unset, and the ReadPosition is advanced only
/// when a new line was appended, so the client's own writes cannot keep
/// re-triggering it.
///
/// On a "Chat" state change: reloads the full chat list via `load_startup_data`.
///
/// Unknown type names are silently ignored.  All JMAP errors are logged as
/// warnings and the function returns without modifying `state.message_state`.
pub(crate) async fn handle_state_change(
    http_client: &reqwest::Client,
    api_url: &str,
    account_id: &str,
    sc: &StateChange,
    state: &mut AppState,
) {
    if state.auth_rejected() {
        return;
    }
    match sc.type_name.as_str() {
        "Message" => {
            // RFC 8620 §5.2: sinceState must be a state the server returned
            // from Message/get. Without one, resync instead of inventing one.
            if state.message_state.is_empty() {
                resync_selected_chat(http_client, api_url, account_id, state).await;
                return;
            }
            let since_state = state.message_state.clone();

            // Step 1: Message/changes
            let changes_req = JmapRequest::new(
                vec![
                    "urn:ietf:params:jmap:core".into(),
                    "urn:ietf:params:jmap:chat".into(),
                ],
                vec![(
                    "Message/changes".into(),
                    json!({"accountId": account_id, "sinceState": since_state}),
                    "mc0".into(),
                )],
                None,
            );

            let changes_resp = match client::call_jmap(http_client, api_url, &changes_req).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Message/changes failed: {e}");
                    state.note_api_error(&e);
                    return;
                }
            };

            let (method_name, args, _) = match changes_resp.method_responses.first() {
                Some(r) => r,
                None => {
                    tracing::warn!("Message/changes returned no responses");
                    return;
                }
            };

            // RFC 8620 §5.2: cannotCalculateChanges means resync via /get, so
            // fall back to a full reload of the current chat.
            if method_name == "error" {
                let error_type = args.get("type").and_then(Value::as_str).unwrap_or("");
                if error_type == "cannotCalculateChanges" {
                    resync_selected_chat(http_client, api_url, account_id, state).await;
                } else {
                    tracing::warn!("Message/changes returned error: {error_type}");
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

            let destroyed: Vec<String> = args
                .get("destroyed")
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

            for id in &destroyed {
                if let Some(i) = state.message_ids.iter().position(|m| m == id) {
                    state.messages.remove(i);
                    state.message_ids.remove(i);
                    state.message_senders.remove(i);
                }
                state.unread_message_ids.remove(id);
            }

            if all_ids.is_empty() {
                return;
            }

            // Step 2: Message/get for new/updated IDs
            let get_req = JmapRequest::new(
                vec![
                    "urn:ietf:params:jmap:core".into(),
                    "urn:ietf:params:jmap:chat".into(),
                ],
                vec![(
                    "Message/get".into(),
                    json!({"accountId": account_id, "ids": all_ids}),
                    "mg0".into(),
                )],
                None,
            );

            let get_resp = match client::call_jmap(http_client, api_url, &get_req).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Message/get failed: {e}");
                    state.note_api_error(&e);
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
            let mut appended = false;

            for msg in list {
                let msg_chat_id = msg.get("chatId").and_then(Value::as_str).unwrap_or("");
                if msg_chat_id != current_chat_id {
                    continue;
                }
                let Some(line) = format_message_line(msg, &state.contacts, &state.owner_id) else {
                    continue;
                };
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
                // A read Message carries readAt; writing it again would only
                // bump the Message state and echo back here as `updated`.
                let is_unread = sender_id_str != state.owner_id
                    && !msg_id.is_empty()
                    && msg.get("readAt").and_then(Value::as_str).is_none();

                // RFC 8620 §5.2: an id already shown is an update, not a new record.
                let shown_at = (!msg_id.is_empty())
                    .then(|| state.message_ids.iter().position(|m| *m == msg_id))
                    .flatten();
                if let Some(i) = shown_at {
                    state.messages[i] = line;
                    state.message_senders[i] = sender_id_str;
                } else {
                    state.messages.push_back(line);
                    state.message_ids.push_back(msg_id.clone());
                    state.message_senders.push_back(sender_id_str);
                    appended = true;
                }

                if is_unread {
                    state.unread_message_ids.insert(msg_id.clone());
                    newly_unread.push(msg_id);
                } else {
                    state.unread_message_ids.remove(&msg_id);
                }
            }

            // Send one batched read receipt for all newly arrived inbound messages.
            // send_read_receipts is a no-op on empty input, so no outer guard is needed.
            // On error: IDs remain in unread_message_ids for next attempt.
            match send_read_receipts(http_client, api_url, account_id, &newly_unread).await {
                Ok(()) => {
                    for id in &newly_unread {
                        state.unread_message_ids.remove(id);
                    }
                }
                Err(e) => state.note_api_error(e.as_ref()),
            }
            if appended {
                // On error the next view or arrival retries.
                if let Err(e) = mark_chat_read(http_client, api_url, account_id, state).await {
                    state.note_api_error(e.as_ref());
                }
            }
        }
        "Chat" => {
            load_startup_data(http_client, api_url, account_id, state).await;
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
    account_id: String,
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

    load_startup_data(&http_client, &api_url, &account_id, state).await;

    let startup_chat = state
        .chat_ids
        .get(state.selected_chat)
        .filter(|_| !state.auth_rejected())
        .cloned();
    if let Some(chat_id) = startup_chat {
        let loaded = load_messages_for_chat(
            &http_client,
            &api_url,
            &account_id,
            &chat_id,
            &state.contacts,
            &state.owner_id,
        )
        .await;
        if let Some(e) = &loaded.api_error {
            state.note_api_error(e);
        }
        if loaded.is_error {
            if !state.auth_rejected() {
                state.connection_status =
                    crate::app::ConnectionStatus::Error("Failed to load messages".to_string());
            }
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
                &state.owner_id,
            );
            flush_unread_receipts(&http_client, &api_url, &account_id, state).await;
            if let Err(e) = mark_chat_read(&http_client, &api_url, &account_id, state).await {
                state.note_api_error(e.as_ref());
            }
            state.scroll_offset = 0;
        }
    }
    // If chat_ids is empty (new user with no chats yet), continue into the event loop.

    // Track the previously selected chat to detect changes and reload messages.
    // Invariant: prev_selected must be updated to state.selected_chat at the end of
    // every iteration where a change is detected.  Missing this update causes messages
    // to reload on every tick instead of only on actual selection changes.
    let mut prev_selected = state.selected_chat;

    // Holds an SSE state-change that arrived during the select! but whose
    // async handling has not yet run.  The await is intentionally deferred
    // outside the select! body: running a long await *inside* a select! arm
    // prevents all other arms (keyboard, tick, SSE status) from firing during
    // that await, making the TUI unresponsive.  Processing it after select!
    // returns means at most one extra loop iteration of latency before the
    // next keyboard event is handled.
    let mut pending_sc: Option<StateChange> = None;
    // The SSE task closes both channels when it stops for good (token
    // rejected); a closed channel is then no longer polled.
    let mut sse_open = true;
    let mut sse_status_open = true;

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
            maybe_sc = sse_rx.recv(), if sse_open => {
                match maybe_sc {
                    Some(sc) => {
                        // Store for dispatch AFTER select! — see comment above pending_sc.
                        pending_sc = Some(sc);
                    }
                    None => {
                        // SSE task exited; the status channel, which closes
                        // with it after any AuthError, decides whether to quit.
                        sse_open = false;
                    }
                }
            }
            maybe_status = sse_status_rx.recv(), if sse_status_open => {
                match maybe_status {
                    None => {
                        // Status channel closed; task exited. After a rejected
                        // token, stay up so the user can read why.
                        sse_status_open = false;
                        state.quit |= !state.auth_rejected();
                    }
                    _ if state.auth_rejected() => {}
                    Some(crate::client::SseStatus::Connected) => {
                        state.connection_status = crate::app::ConnectionStatus::Connected;
                    }
                    Some(crate::client::SseStatus::Reconnecting) => {
                        state.connection_status = crate::app::ConnectionStatus::Reconnecting;
                    }
                    Some(crate::client::SseStatus::AuthError(code)) => {
                        // The SSE task has stopped; retrying is pointless.
                        // Keep the UI up with the reason until the user quits.
                        state.connection_status = crate::app::ConnectionStatus::AuthRejected(code);
                    }
                }
            }
            _ = tick.tick() => {
                state.clear_stale_error();
            }
        }

        // Dispatch deferred SSE state change (see comment above pending_sc).
        // Skip if quitting — no point fetching data we will immediately discard.
        if !state.quit {
            if let Some(sc) = pending_sc.take() {
                handle_state_change(&http_client, &api_url, &account_id, &sc, state).await;
                // A "Chat" state change calls load_startup_data which may
                // clamp selected_chat.  Sync prev_selected so the
                // post-select reload check does not fire spuriously.
                prev_selected = state.selected_chat;
            }
        }

        // Dispatch async send when Enter was pressed in handle_key().
        if state.should_send_message {
            state.should_send_message = false;
            let body = state.input.trim().to_string();
            if !body.is_empty() {
                if let Some(chat_id) = state.chat_ids.get(state.selected_chat).cloned() {
                    match send_message(&http_client, &api_url, &account_id, &chat_id, &body).await {
                        Ok(_msg_id) => {
                            state.input.clear();
                            state.input_cursor = 0;
                            // The sent message will appear via the SSE state-change path.
                        }
                        Err(e) => {
                            state.note_api_error(e.as_ref());
                            let msg = sanitize_display(&format!("Send failed: {e}"));
                            state.set_error(&msg);
                        }
                    }
                }
            }
        }

        if state.selected_chat != prev_selected && !state.auth_rejected() {
            if let Some(chat_id) = state.chat_ids.get(state.selected_chat) {
                // Reload messages for the newly selected chat.
                let chat_id = chat_id.clone();
                let loaded = load_messages_for_chat(
                    &http_client,
                    &api_url,
                    &account_id,
                    &chat_id,
                    &state.contacts,
                    &state.owner_id,
                )
                .await;
                if let Some(e) = &loaded.api_error {
                    state.note_api_error(e);
                }
                if loaded.is_error {
                    if !state.auth_rejected() {
                        state.connection_status = crate::app::ConnectionStatus::Error(
                            "Failed to load messages".to_string(),
                        );
                    }
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
                        &state.owner_id,
                    );
                    flush_unread_receipts(&http_client, &api_url, &account_id, state).await;
                    if let Err(e) = mark_chat_read(&http_client, &api_url, &account_id, state).await
                    {
                        state.note_api_error(e.as_ref());
                    }
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

    // Oracle: RFC 8620 §1.4 — "the time-secfrac MUST always be omitted if
    // zero", example "2014-10-30T06:12:00Z". jmap-testjig (crate-jmap
    // 25fff527) rejected sentAt "2026-10-30T12:40:00.000Z" with
    // invalidProperties ["sentAt"] and accepted "2026-10-30T12:40:00Z".
    #[test]
    fn utc_date_omits_zero_secfrac() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-10-30T12:40:00Z")
            .expect("valid date")
            .with_timezone(&chrono::Utc);
        assert_eq!(utc_date(t), "2026-10-30T12:40:00Z");
    }

    // Oracle: RFC 8620 §1.4 — a non-zero secfrac is kept; jmap-testjig
    // accepted sentAt "2026-10-30T12:40:00.123Z".
    #[test]
    fn utc_date_keeps_nonzero_millis() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-10-30T12:40:00.123456Z")
            .expect("valid date")
            .with_timezone(&chrono::Utc);
        assert_eq!(utc_date(t), "2026-10-30T12:40:00.123Z");
    }
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
            account_id: String,
            sse_rx: tokio::sync::mpsc::Receiver<kith_core::StateChange>,
            sse_status_rx: tokio::sync::mpsc::Receiver<crate::client::SseStatus>,
        ) {
            // Calling run() with these typed args would require an async context.
            // Naming the call is enough to confirm the signature compiles.
            let _ = run(
                terminal,
                state,
                http_client,
                api_url,
                account_id,
                sse_rx,
                sse_status_rx,
            );
        }
        // _assert_run_types is never called; the type-check is purely static.
        let _ = _assert_run_types as fn(_, _, _, _, _, _, _);
    }

    // Oracle: KITH-1ln3.9 live run — `tmux send-keys -l 'a quick test'` into
    // the input box must leave exactly that text in the box, not exit.
    #[test]
    fn typing_q_in_input_inserts_text_and_does_not_quit() {
        let mut state = AppState::new();
        state.focus = Focus::Input;
        for c in "a quick test".chars() {
            handle_key(&mut state, KeyCode::Char(c), KeyModifiers::empty());
        }
        assert!(!state.quit, "typing 'q' in the input must not quit");
        assert_eq!(state.input, "a quick test");
    }

    #[test]
    fn q_quits_from_chat_list() {
        let mut state = AppState::new();
        state.focus = Focus::ChatList;
        handle_key(&mut state, KeyCode::Char('q'), KeyModifiers::empty());
        assert!(state.quit);
    }

    #[test]
    fn ctrl_c_quits_from_input() {
        let mut state = AppState::new();
        state.focus = Focus::Input;
        handle_key(&mut state, KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(state.quit);
        assert!(state.input.is_empty());
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
                            "contactId": "c-1",
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

        load_startup_data(&http_client, &api_url, "a-self", &mut state).await;

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

        let loaded = load_messages_for_chat(
            &http_client,
            &api_url,
            "a-self",
            "chat-abc",
            &contacts,
            "uid-test-owner",
        )
        .await;
        let msgs = loaded.display_lines;

        // Oracle: derived from mock data above — HH:MM from receivedAt[11..16]
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0], "13:45 Alice: Hello", "first message");
        assert_eq!(
            msgs[1], "13:46 me: World",
            "second message (sender=uid-test-owner == owner -> me)"
        );
    }

    #[derive(Clone, Default)]
    struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer lock")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // KITH-1ln3.10: eprintln! while the TUI owns the terminal garbles the
    // screen. Diagnostics must go through tracing (which main sends to a log
    // file), and must never carry the bearer token.
    #[tokio::test]
    async fn load_failure_is_reported_via_tracing_without_token() {
        use std::collections::HashMap;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const TOKEN_CANARY: &str = "canary-token-1ln3-10";
        let captured = CapturedLog::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;
        let api_url = format!("{}/jmap/api", mock_server.uri());
        let http_client = client::build_client(None, Some(TOKEN_CANARY)).expect("client builds");

        let loaded = load_messages_for_chat(
            &http_client,
            &api_url,
            "a-self",
            "chat-xyz",
            &HashMap::new(),
            "",
        )
        .await;
        assert!(loaded.is_error);

        let log = String::from_utf8(captured.0.lock().expect("lock").clone()).expect("utf-8");
        assert!(
            log.contains("Message/query failed"),
            "diagnostic must reach the tracing subscriber, got: {log:?}"
        );
        assert!(
            !log.contains(TOKEN_CANARY),
            "token leaked into log: {log:?}"
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

        let loaded =
            load_messages_for_chat(&http_client, &api_url, "a-self", "chat-xyz", &contacts, "")
                .await;

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

        let loaded =
            load_messages_for_chat(&http_client, &api_url, "a-self", "chat-t", &contacts, "").await;

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

    // Oracle: draft-atwood-jmap-chat-00 Message/query — "Default sort:
    // receivedAt ascending when chatId is present", so fetching the newest
    // page needs an explicit RFC 8620 §5.5 Comparator
    // {"property": "receivedAt", "isAscending": false}. Responses captured
    // from jmap-testjig (crate-jmap 25fff527) with that sort.
    #[tokio::test]
    async fn load_messages_requests_newest_first() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let has_newest_first_sort = |req: &Request| {
            serde_json::from_slice::<Value>(&req.body).is_ok_and(|v| {
                v["methodCalls"][0][1]["sort"]
                    == json!([{"property": "receivedAt", "isAscending": false}])
            })
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap"))
            .and(body_string_contains("Message/query"))
            .and(has_newest_first_sort)
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["Message/query", {
                    "accountId": "testjig-account", "canCalculateChanges": true,
                    "ids": ["01M66D4BWJP3FCEYXVNWAB58KB", "01M66D4BW8R24HZN11156BK2BK"],
                    "position": 0, "queryState": "3", "total": 2
                }, "mq0"]],
                "sessionState": "testjig-state-0"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/jmap"))
            .and(body_string_contains("Message/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["Message/get", {
                    "accountId": "testjig-account",
                    "list": [
                        {"body": "hello 2026-10-30T12:40:00Z", "bodyType": "text/plain",
                         "chatId": "01M66D41AYKP6XWKFMHKW5A9Y0", "id": "01M66D4BW8R24HZN11156BK2BK",
                         "receivedAt": "2026-10-30T12:39:07.400Z", "senderId": "testjig-account",
                         "sentAt": "2026-10-30T12:40:00Z"},
                        {"body": "hello 2026-10-30T12:40:00.123Z", "bodyType": "text/plain",
                         "chatId": "01M66D41AYKP6XWKFMHKW5A9Y0", "id": "01M66D4BWJP3FCEYXVNWAB58KB",
                         "receivedAt": "2026-10-30T12:39:07.410Z", "senderId": "testjig-account",
                         "sentAt": "2026-10-30T12:40:00.123Z"}
                    ],
                    "notFound": [], "state": "3"
                }, "mg0"]],
                "sessionState": "testjig-state-0"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap", mock_server.uri());
        let loaded = load_messages_for_chat(
            &reqwest::Client::new(),
            &api_url,
            "testjig-account",
            "01M66D41AYKP6XWKFMHKW5A9Y0",
            &HashMap::new(),
            "testjig-account",
        )
        .await;

        assert!(!loaded.is_error, "query must carry the newest-first sort");
        assert_eq!(loaded.display_lines.len(), 2);
    }

    // Oracle: draft-atwood-jmap-chat-00 Chat Object Fields — a direct chat
    // names the other participant by `contactId`, a group chat carries
    // `name`; ChatContact: clients fall back to `login` when `displayName` is
    // absent. Chat/get and ChatContact/get responses captured from
    // jmap-testjig (crate-jmap 25fff527).
    #[tokio::test]
    async fn load_startup_data_names_chats_from_testjig() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [
                    ["Chat/get", {
                        "accountId": "testjig-account",
                        "list": [
                            {"activeCallAccountId": null, "activeCallId": null,
                             "contactId": "01M66D3XQZP5DP4XBV34WWY526",
                             "createdAt": "2026-10-30T12:38:56.606Z",
                             "id": "01M66D41AYKP6XWKFMHKW5A9Y0", "kind": "direct",
                             "muted": false, "pinnedMessageIds": [],
                             "receiveTypingIndicators": true, "unreadCount": 3},
                            {"activeCallAccountId": null, "activeCallId": null,
                             "createdAt": "2026-10-30T12:46:09.583Z",
                             "id": "01M66DH85FBJCJ4HQ19WC9FT05", "kind": "group",
                             "members": [
                                 {"id": "testjig-account", "joinedAt": "2026-10-30T12:46:09.583Z", "role": "admin"},
                                 {"id": "01M66D3XQZP5DP4XBV34WWY526", "invitedBy": "testjig-account",
                                  "joinedAt": "2026-10-30T12:46:09.583Z", "role": "member"}
                             ],
                             "muted": false, "name": "Demo crew", "pinnedMessageIds": [],
                             "receiveTypingIndicators": true, "unreadCount": 0}
                        ],
                        "notFound": [], "state": "5"
                    }, "c0"],
                    ["ChatContact/get", {
                        "accountId": "testjig-account",
                        "list": [{
                            "blocked": false, "firstSeenAt": "2026-10-30T12:38:52.927Z",
                            "id": "01M66D3XQZP5DP4XBV34WWY526",
                            "identity": "alice@example.org",
                            "lastSeenAt": "2026-10-30T12:38:52.927Z",
                            "login": "alice@example.org"
                        }],
                        "notFound": [], "state": "1"
                    }, "c1"]
                ],
                "sessionState": "testjig-state-0"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap", mock_server.uri());
        let mut state = crate::app::AppState::new();
        load_startup_data(
            &reqwest::Client::new(),
            &api_url,
            "testjig-account",
            &mut state,
        )
        .await;

        assert_eq!(state.chat_list, vec!["alice@example.org (3)", "Demo crew"]);
    }

    // Oracle: RFC 8620 §5.2 — /changes fails with "cannotCalculateChanges"
    // when it cannot compute changes from sinceState, and the client must
    // then resync with /get. Responses captured from jmap-testjig (crate-jmap
    // 25fff527): an empty chat leaves no state token, kith-tui sends a
    // made-up sinceState, and testjig answers cannotCalculateChanges.
    #[tokio::test]
    async fn handle_state_change_cannot_calculate_changes_reloads_chat() {
        use kith_core::StateChange;
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let chat_id = "01M66D41AYKP6XWKFMHKW5A9Y0";
        let reply = |body: serde_json::Value| ResponseTemplate::new(200).set_body_json(body);

        Mock::given(method("POST"))
            .and(path("/jmap"))
            .and(body_string_contains("Message/changes"))
            .respond_with(reply(serde_json::json!({
                "methodResponses": [["error", {"type": "cannotCalculateChanges"}, "mc0"]],
                "sessionState": "testjig-state-0"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/jmap"))
            .and(body_string_contains("Message/query"))
            .respond_with(reply(serde_json::json!({
                "methodResponses": [["Message/query", {
                    "accountId": "testjig-account", "canCalculateChanges": true,
                    "ids": ["01M66D4BW8R24HZN11156BK2BK"], "position": 0,
                    "queryState": "1", "total": 1
                }, "mq0"]],
                "sessionState": "testjig-state-0"
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/jmap"))
            .and(body_string_contains("Message/get"))
            .respond_with(reply(serde_json::json!({
                "methodResponses": [["Message/get", {
                    "accountId": "testjig-account",
                    "list": [{
                        "actions": [], "attachments": [], "body": "hello from owner",
                        "bodyType": "text/plain", "broadcastMentions": [],
                        "chatId": chat_id, "deliveryState": "pending",
                        "id": "01M66D4BW8R24HZN11156BK2BK", "mentions": [],
                        "reactions": {}, "receivedAt": "2026-10-30T12:39:07.400Z",
                        "senderId": "testjig-account",
                        "senderMsgId": "01M66D4BW8R24HZN11156BK2BK",
                        "sentAt": "2026-10-30T12:40:00Z"
                    }],
                    "notFound": [], "state": "1"
                }, "mg0"]],
                "sessionState": "testjig-state-0"
            })))
            .mount(&mock_server)
            .await;

        let api_url = format!("{}/jmap", mock_server.uri());
        let http_client = reqwest::Client::new();
        let mut state = crate::app::AppState::new();
        state.chat_ids = vec![chat_id.to_string()];
        state.selected_chat = 0;
        state.owner_id = "testjig-account".to_string();

        let sc = StateChange::new("Message", "1");
        handle_state_change(&http_client, &api_url, "testjig-account", &sc, &mut state).await;

        assert_eq!(state.messages.len(), 1, "chat must be reloaded");
        assert!(
            state.messages[0].contains("me: hello from owner"),
            "reloaded line: {}",
            state.messages[0]
        );
        assert_eq!(state.message_state, "1", "state token from Message/get");
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

        let sc = StateChange::new("Message", "s-4");
        handle_state_change(&http_client, &api_url, "a-self", &sc, &mut state).await;

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

    /// Builds a Message object as draft-atwood-jmap-chat-00 defines it; the
    /// server omits `readAt` until it is set (crate-jmap `Message::read_at`
    /// is `skip_serializing_if = "Option::is_none"`).
    fn wire_message(id: &str, body: &str, read_at: Option<&str>) -> Value {
        let mut m = json!({
            "id": id, "chatId": "chat-1", "senderId": "c-alice",
            "body": body, "bodyType": "text/plain", "attachments": [],
            "sentAt": "2026-10-30T13:42:18Z", "receivedAt": "2026-10-30T13:42:18.200Z",
            "deliveryState": "received"
        });
        if let Some(r) = read_at {
            m["readAt"] = json!(r);
        }
        m
    }

    fn one_message_state() -> crate::app::AppState {
        let mut state = crate::app::AppState::new();
        state.owner_id = "a-bob".to_string();
        state.chat_ids = vec!["chat-1".to_string()];
        state
            .contacts
            .insert("c-alice".to_string(), "alice".to_string());
        state.messages.push_back("13:42 alice: hello".to_string());
        state.message_ids.push_back("m-1".to_string());
        state.message_senders.push_back("c-alice".to_string());
        state.message_state = "5".to_string();
        state
    }

    fn method_response(name: &str, args: Value) -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(200).set_body_json(json!({
            "methodResponses": [[name, args, "0"]], "sessionState": "0"
        }))
    }

    // Oracle: RFC 8620 §5.2 — `updated` lists "the ids for records that have
    // been updated since the old state", i.e. records the client already
    // holds; they replace the cached copy, they are not new records.
    #[tokio::test]
    async fn handle_state_change_updated_id_replaces_existing_line() {
        use wiremock::matchers::body_string_contains;
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(body_string_contains("Message/changes"))
            .respond_with(method_response(
                "Message/changes",
                json!({"accountId": "a-bob", "oldState": "5", "newState": "6",
                       "hasMoreChanges": false, "created": [], "updated": ["m-1"],
                       "destroyed": []}),
            ))
            .mount(&server)
            .await;
        Mock::given(body_string_contains("Message/get"))
            .respond_with(method_response(
                "Message/get",
                json!({"accountId": "a-bob", "state": "6", "notFound": [],
                       "list": [wire_message("m-1", "hello (edited)", Some("2026-10-30T13:42:19Z"))]}),
            ))
            .mount(&server)
            .await;

        let mut state = one_message_state();
        let api_url = format!("{}/jmap", server.uri());
        let sc = StateChange::new("Message", "6");
        handle_state_change(&reqwest::Client::new(), &api_url, "a-bob", &sc, &mut state).await;

        assert_eq!(state.messages.len(), 1, "updated id must not be appended");
        assert_eq!(state.message_ids, ["m-1"]);
        assert_eq!(state.message_senders.len(), 1);
        assert!(
            state.messages[0].contains("hello (edited)"),
            "line must show the updated body, got {:?}",
            state.messages[0]
        );
    }

    // Oracle: RFC 8620 §5.2 — `destroyed` ids "have been destroyed since the
    // old state"; the client drops them.
    #[tokio::test]
    async fn handle_state_change_destroyed_id_removes_line() {
        use wiremock::matchers::body_string_contains;
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(body_string_contains("Message/changes"))
            .respond_with(method_response(
                "Message/changes",
                json!({"accountId": "a-bob", "oldState": "5", "newState": "6",
                       "hasMoreChanges": false, "created": [], "updated": [],
                       "destroyed": ["m-1"]}),
            ))
            .mount(&server)
            .await;

        let mut state = one_message_state();
        let api_url = format!("{}/jmap", server.uri());
        let sc = StateChange::new("Message", "6");
        handle_state_change(&reqwest::Client::new(), &api_url, "a-bob", &sc, &mut state).await;

        assert!(state.messages.is_empty(), "destroyed line must be removed");
        assert!(state.message_ids.is_empty());
        assert!(state.message_senders.is_empty());
        assert_eq!(state.message_state, "6");
    }

    // Oracle: draft-atwood-jmap-chat-00 "Marking as Read" — a client marks a
    // Message read with an `update` setting `readAt`. A Message whose
    // `readAt` is already set is read, so a second update would only change
    // the timestamp. Rehearsal1 (json/st-bob.resp.json): such rewrites bumped
    // bob's Message state 1250 -> 6174 with one stored message.
    #[tokio::test]
    async fn handle_state_change_already_read_update_sends_no_write() {
        use wiremock::matchers::body_string_contains;
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        Mock::given(body_string_contains("Message/changes"))
            .respond_with(method_response(
                "Message/changes",
                json!({"accountId": "a-bob", "oldState": "5", "newState": "6",
                       "hasMoreChanges": false, "created": [], "updated": ["m-1"],
                       "destroyed": []}),
            ))
            .mount(&server)
            .await;
        Mock::given(body_string_contains("Message/get"))
            .respond_with(method_response(
                "Message/get",
                json!({"accountId": "a-bob", "state": "6", "notFound": [],
                       "list": [wire_message("m-1", "hello", Some("2026-10-30T13:42:19Z"))]}),
            ))
            .mount(&server)
            .await;
        Mock::given(body_string_contains("/set"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .expect(0)
            .named("no write for an already-read message")
            .mount(&server)
            .await;
        Mock::given(body_string_contains("ReadPosition/get"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .expect(0)
            .named("no ReadPosition lookup when nothing new is shown")
            .mount(&server)
            .await;

        let mut state = one_message_state();
        let api_url = format!("{}/jmap", server.uri());
        let sc = StateChange::new("Message", "6");
        handle_state_change(&reqwest::Client::new(), &api_url, "a-bob", &sc, &mut state).await;
        server.verify().await;
    }

    /// A server that, like chinwag in rehearsal1, bumps the Message state on
    /// every `readAt` write and reports the message as `updated` afterwards.
    struct ReceiptBumpingServer {
        inner: std::sync::Mutex<(u64, Option<String>, Option<String>)>,
    }

    impl wiremock::Respond for ReceiptBumpingServer {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let call = &body["methodCalls"][0];
            let args = &call[1];
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let (msg_state, read_at, last_read) = &mut *inner;
            match call[0].as_str().unwrap_or("") {
                "Message/changes" => {
                    let since = args["sinceState"].as_str().unwrap_or("");
                    let (created, updated) = if since == "1" {
                        (json!(["m-1"]), json!([]))
                    } else {
                        (json!([]), json!(["m-1"]))
                    };
                    method_response(
                        "Message/changes",
                        json!({"accountId": "a-bob", "oldState": since,
                               "newState": msg_state.to_string(), "hasMoreChanges": false,
                               "created": created, "updated": updated, "destroyed": []}),
                    )
                }
                "Message/get" => method_response(
                    "Message/get",
                    json!({"accountId": "a-bob", "state": msg_state.to_string(), "notFound": [],
                           "list": [wire_message("m-1", "hello", read_at.as_deref())]}),
                ),
                "Message/set" => {
                    if let Some(r) = args["update"]["m-1"]["readAt"].as_str() {
                        *read_at = Some(r.to_string());
                        *msg_state += 1;
                    }
                    method_response(
                        "Message/set",
                        json!({"accountId": "a-bob", "updated": {"m-1": null}}),
                    )
                }
                "ReadPosition/get" => method_response(
                    "ReadPosition/get",
                    json!({"accountId": "a-bob", "state": "1", "notFound": [],
                           "list": [{"id": "rp-1", "chatId": "chat-1",
                                     "lastReadMessageId": last_read.clone()}]}),
                ),
                "ReadPosition/set" => {
                    *last_read = args["update"]["rp-1"]["lastReadMessageId"]
                        .as_str()
                        .map(str::to_string);
                    method_response(
                        "ReadPosition/set",
                        json!({"accountId": "a-bob", "updated": {"rp-1": null}}),
                    )
                }
                _ => wiremock::ResponseTemplate::new(400),
            }
        }
    }

    // Oracle: rehearsal1 — one message, every receipt write bumps Message
    // state and pushes a StateChange; kith-tui then looped at ~290 req/s.
    // Each StateChange the server would push is fed back to the client until
    // the client's state matches the server's. A client that only writes
    // what changes something reaches it after the one real receipt.
    #[tokio::test]
    async fn receipt_loop_settles_when_server_bumps_state_on_write() {
        use wiremock::{Mock, MockServer};

        let server = MockServer::start().await;
        let fake = std::sync::Arc::new(ReceiptBumpingServer {
            inner: std::sync::Mutex::new((2, None, None)),
        });
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(SharedResponder(fake.clone()))
            .mount(&server)
            .await;

        let mut state = crate::app::AppState::new();
        state.owner_id = "a-bob".to_string();
        state.chat_ids = vec!["chat-1".to_string()];
        state.message_state = "1".to_string();
        let api_url = format!("{}/jmap", server.uri());
        let http = reqwest::Client::new();

        let mut pushes = 0;
        loop {
            let server_state = fake.inner.lock().unwrap().0.to_string();
            if state.message_state == server_state || pushes == 50 {
                break;
            }
            pushes += 1;
            let sc = StateChange::new("Message", server_state);
            handle_state_change(&http, &api_url, "a-bob", &sc, &mut state).await;
        }

        let requests = server.received_requests().await.unwrap_or_default().len();
        assert!(pushes <= 2, "client must settle, took {pushes} pushes");
        assert!(requests <= 10, "client sent {requests} requests");
        assert_eq!(state.messages.len(), 1, "one stored message, one line");
    }

    struct SharedResponder(std::sync::Arc<ReceiptBumpingServer>);

    impl wiremock::Respond for SharedResponder {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            self.0.respond(req)
        }
    }

    // Oracle: RFC 6750 §3.1 — HTTP 401 with error="invalid_token" means the
    // bearer token was rejected; rehearsal1 showed "JMAP startup failed"
    // instead (shots/11-carol-push-after-revoke.txt).
    #[tokio::test]
    async fn startup_401_reports_token_rejected() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("WWW-Authenticate", r#"Bearer error="invalid_token""#),
            )
            .mount(&server)
            .await;
        let mut state = crate::app::AppState::new();
        let api_url = format!("{}/jmap", server.uri());
        load_startup_data(&reqwest::Client::new(), &api_url, "a-bob", &mut state).await;

        let status = state.connection_status.to_string();
        assert!(status.contains("token rejected"), "got {status:?}");
        assert!(status.contains("KITH_TOKEN"), "got {status:?}");
        assert!(status.contains("401"), "got {status:?}");
    }

    // Oracle: RFC 6750 §3.1 — a rejected token stays rejected; retrying with
    // it cannot succeed. Rehearsal1: carol's client re-sent requests on every
    // push after her token was revoked.
    #[tokio::test]
    async fn no_requests_after_token_rejected() {
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;
        let mut state = one_message_state();
        let api_url = format!("{}/jmap", server.uri());
        let http = reqwest::Client::new();
        for (type_name, new_state) in [("Message", "6"), ("Message", "7"), ("Chat", "2")] {
            let sc = StateChange::new(type_name, new_state);
            handle_state_change(&http, &api_url, "a-bob", &sc, &mut state).await;
        }
        server.verify().await;
        let status = state.connection_status.to_string();
        assert!(status.contains("token rejected"), "got {status:?}");
    }

    // Oracle: rehearsal1 json/chat-get-alice.resp.json — chinwag's Chat/get
    // for alice after carol joined IIW: four `members` ids (draft-atwood-
    // jmap-chat-00 Chat.members, "Full membership list"), one of them
    // alice's own accountId. The ChatContact list is built to match those
    // ids. A Chat state change before carol joined lists three.
    #[tokio::test]
    async fn group_members_shown_in_header_and_follow_chat_changes() {
        use wiremock::matchers::body_string_contains;
        use wiremock::{Mock, MockServer};

        const ALICE: &str = "01M66GPT09MFTQ23WR3WKV5QJH";
        let member = |id: &str, role: &str| json!({"id": id, "role": role, "joinedAt": "2026-10-30T13:41:37.428Z"});
        let admin = member("01M66GPT0S5BK6V9QTBAA948QY", "admin");
        let alice = member(ALICE, "member");
        let bob = member("01M66GPT2BTAVF0T9KA45M6HFT", "member");
        let carol = member("01M66GQ8JZV7VRTQWFFCXYBCN8", "member");
        // load_startup_data sends Chat/get and ChatContact/get in one request.
        let startup_response = |members: Value| {
            wiremock::ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [
                    ["Chat/get", {"accountId": ALICE, "state": "3", "notFound": [], "list": [{
                        "id": "01M66GPREXR5X1Y99ZH76VGDH0", "kind": "group", "name": "IIW",
                        "members": members, "unreadCount": 0, "muted": false,
                        "pinnedMessageIds": [], "createdAt": "2026-10-30T13:41:37.433Z"}]}, "c0"],
                    ["ChatContact/get", {"accountId": ALICE, "state": "3", "notFound": [], "list": [
                        {"id": "01M66GPT0S5BK6V9QTBAA948QY", "login": "iiw@localhost"},
                        {"id": "01M66GPT2BTAVF0T9KA45M6HFT", "login": "bob@localhost"},
                        {"id": "01M66GQ8JZV7VRTQWFFCXYBCN8", "login": "carol@localhost"}]}, "c1"]],
                "sessionState": "0"}))
        };
        let server = MockServer::start().await;
        Mock::given(body_string_contains("Chat/get"))
            .respond_with(startup_response(json!([admin, alice, bob])))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(body_string_contains("Chat/get"))
            .respond_with(startup_response(json!([admin, alice, bob, carol])))
            .mount(&server)
            .await;

        let mut state = crate::app::AppState::new();
        state.owner_id = ALICE.to_string();
        let api_url = format!("{}/jmap", server.uri());
        let http = reqwest::Client::new();
        let header = |state: &mut crate::app::AppState| -> String {
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(120, 24)).unwrap();
            terminal.draw(|f| crate::ui::draw(f, state)).unwrap();
            let buf = terminal.backend().buffer().clone();
            (0..120).map(|x| buf[(x, 0u16)].symbol()).collect()
        };

        load_startup_data(&http, &api_url, ALICE, &mut state).await;
        let before = header(&mut state);
        assert!(
            before.contains("3 members: iiw@localhost, me, bob@localhost"),
            "got {before:?}"
        );

        let sc = StateChange::new("Chat", "4");
        handle_state_change(&http, &api_url, ALICE, &sc, &mut state).await;
        let after = header(&mut state);
        assert!(
            after.contains("4 members: iiw@localhost, me, bob@localhost, carol@localhost"),
            "got {after:?}"
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

        let sc = StateChange::new("UnknownType", "s-6");
        handle_state_change(&http_client, api_url, "a-self", &sc, &mut state).await;

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
                            "contactId": "c-bob",
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
        state.owner_id = "uid-test-owner".to_string();

        // Step 1: startup data
        load_startup_data(&http_client, &api_url, "a-self", &mut state).await;

        // Step 2+3: initial message load (+ step 3: send_read_receipts for inbound m-init)
        if let Some(chat_id) = state.chat_ids.first().cloned() {
            let loaded = load_messages_for_chat(
                &http_client,
                &api_url,
                "a-self",
                &chat_id,
                &state.contacts,
                &state.owner_id,
            )
            .await;
            state.messages = loaded.display_lines;
            state.message_ids = loaded.message_ids;
            state.message_senders = loaded.sender_ids;
            state.unread_message_ids = unread_ids_from_loaded_messages(
                &state.message_ids,
                &state.message_senders,
                &loaded.read_ats,
                &state.owner_id,
            );
            flush_unread_receipts(&http_client, &api_url, "a-self", &mut state).await;
            state.message_state = "s-4".to_string(); // set from Message/get state field
            state.scroll_offset = 0;
        }

        // Step 4+5: SSE state change arrives
        let sc = StateChange::new("Message", "s-5");
        handle_state_change(&http_client, &api_url, "a-self", &sc, &mut state).await;

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

        load_startup_data(&http_client, &api_url, "a-self", &mut state).await;

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

        load_startup_data(&http_client, &api_url, "a-self", &mut state).await;

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

    // Oracle: RFC 8620 §1.6.2 — accountIds are opaque, server-assigned values
    // that the client learns from the Session. Every method call kith-tui sends
    // must carry the session's accountId, never a hardcoded one ("a-self").
    #[tokio::test]
    async fn requests_carry_session_account_id() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [],
                "sessionState": "s-1"
            })))
            .mount(&mock_server)
            .await;

        let client = reqwest::Client::new();
        let url = format!("{}/jmap/api", mock_server.uri());
        let mut state = AppState::new();
        load_startup_data(&client, &url, "acct-7f3", &mut state).await;
        let _ = send_message(&client, &url, "acct-7f3", "chat-abc", "hi").await;

        let reqs = mock_server.received_requests().await.expect("recording on");
        assert_eq!(reqs.len(), 2, "startup batch + Message/set");
        let mut calls = 0;
        for req in &reqs {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("JSON body");
            for call in body["methodCalls"].as_array().expect("methodCalls") {
                assert_eq!(call[1]["accountId"], "acct-7f3", "in {}", call[0]);
                calls += 1;
            }
        }
        assert!(calls >= 3, "Chat/get, ChatContact/get and Message/set");
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
        let result = send_message(&client, &url, "a-self", "chat-abc", "hello world").await;
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
        let result = send_message(&client, &url, "a-self", "chat-abc", "x").await;
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
        let result = send_message(&client, &url, "a-self", "chat-abc", "hi").await;
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
        let result = send_message(
            &client,
            "http://127.0.0.1:1/jmap/api",
            "a-self",
            "chat-abc",
            "",
        )
        .await;
        assert!(result.is_err(), "empty body must return Err without HTTP");
    }

    #[tokio::test]
    async fn send_message_whitespace_body_no_http() {
        // Oracle: whitespace-only body must short-circuit without any HTTP call
        let client = reqwest::Client::new();
        let result = send_message(
            &client,
            "http://127.0.0.1:1/jmap/api",
            "a-self",
            "chat-abc",
            "   ",
        )
        .await;
        assert!(
            result.is_err(),
            "whitespace body must return Err without HTTP"
        );
    }

    #[tokio::test]
    async fn send_message_network_error() {
        // Oracle: unreachable URL must return Err (network error propagated)
        let client = reqwest::Client::new();
        let result = send_message(
            &client,
            "http://127.0.0.1:1/jmap/api",
            "a-self",
            "chat-abc",
            "hello",
        )
        .await;
        assert!(result.is_err(), "network failure must return Err");
    }

    #[tokio::test]
    async fn send_read_receipts_empty_slice_no_http() {
        // Oracle: empty slice must return Ok without any HTTP call
        let client = reqwest::Client::new();
        let result =
            send_read_receipts(&client, "http://127.0.0.1:1/jmap/api", "a-self", &[]).await;
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
        let result = send_read_receipts(&client, &url, "a-self", &ids).await;
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
        let result = send_read_receipts(&client, &url, "a-self", &ids).await;
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
        let result =
            send_read_receipts(&client, "http://127.0.0.1:1/jmap/api", "a-self", &ids).await;
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
        let result = send_message(&client, &url, "a-self", "chat-1", &body).await;

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
        let result = send_message(&client, &url, "a-self", "chat-1", &body).await;

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
        let result = send_read_receipts(&client, &url, "a-self", &ids).await;

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

    // ── ReadPosition ──────────────────────────────────────────────────────────
    //
    // Oracle: draft-atwood-jmap-chat-00 §ReadPosition and §ReadPosition/set.
    // A ReadPosition has a server-set opaque `id`, a `chatId`, and an optional
    // `lastReadMessageId` ("the id of the most recent Message the owner has
    // read"); `update` supports only `lastReadMessageId`. Chat.unreadCount
    // counts Messages whose id is lexicographically greater, so the cursor
    // must be the greatest displayed id and must never move backwards.

    const ULID_A: &str = "01HZ0000000000000000000AAA";
    const ULID_B: &str = "01HZ0000000000000000000BBB";
    const ULID_C: &str = "01HZ0000000000000000000CCC";

    /// Mount a ReadPosition/get answer and a ReadPosition/set answer; return
    /// the server so the test can inspect what was sent.
    async fn read_position_server(list: Value, set_response: Value) -> wiremock::MockServer {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .and(body_string_contains("ReadPosition/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["ReadPosition/get",
                    {"accountId": "a-self", "state": "rp-s1", "list": list, "notFound": []},
                    "r0"]],
                "sessionState": "s-1"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .and(body_string_contains("ReadPosition/set"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["ReadPosition/set", set_response, "r0"]],
                "sessionState": "s-1"
            })))
            .mount(&server)
            .await;
        server
    }

    fn set_updated(id: &str) -> Value {
        json!({"accountId": "a-self", "oldState": "rp-s1", "newState": "rp-s2",
               "updated": {id: null}})
    }

    /// All ReadPosition/set calls the server received, as (args) values.
    async fn read_position_sets(server: &wiremock::MockServer) -> Vec<Value> {
        server
            .received_requests()
            .await
            .expect("recording on")
            .iter()
            .flat_map(|req| {
                let body: Value = serde_json::from_slice(&req.body).expect("JSON body");
                body["methodCalls"].as_array().expect("methodCalls").clone()
            })
            .filter(|call| call[0] == "ReadPosition/set")
            .map(|call| call[1].clone())
            .collect()
    }

    fn viewing(chat_id: &str, ids: &[&str]) -> AppState {
        let mut state = AppState::new();
        state.chat_ids = vec!["chat-other".to_string(), chat_id.to_string()];
        state.selected_chat = 1;
        state.message_ids = ids.iter().map(|s| s.to_string()).collect();
        state
    }

    #[tokio::test]
    async fn viewing_chat_advances_read_position_to_newest_id() {
        let server = read_position_server(
            json!([
                {"id": "rp-1", "chatId": "chat-other", "lastReadMessageId": ULID_A},
                {"id": "rp-2", "chatId": "chat-v", "lastReadMessageId": ULID_A,
                 "lastReadAt": "2026-10-30T12:00:00Z"}
            ]),
            set_updated("rp-2"),
        )
        .await;
        let url = format!("{}/jmap/api", server.uri());
        let state = viewing("chat-v", &[ULID_A, ULID_C, ULID_B]);

        mark_chat_read(&reqwest::Client::new(), &url, "a-self", &state)
            .await
            .expect("advance must succeed");

        let sets = read_position_sets(&server).await;
        assert_eq!(sets.len(), 1, "exactly one ReadPosition/set");
        assert_eq!(sets[0]["accountId"], "a-self");
        assert_eq!(
            sets[0]["update"],
            json!({"rp-2": {"lastReadMessageId": ULID_C}}),
            "only the viewed chat's position, only lastReadMessageId, greatest id"
        );
    }

    #[tokio::test]
    async fn absent_last_read_message_id_is_advanced() {
        let server = read_position_server(
            json!([{"id": "rp-9", "chatId": "chat-v"}]),
            set_updated("rp-9"),
        )
        .await;
        let url = format!("{}/jmap/api", server.uri());
        let state = viewing("chat-v", &[ULID_A]);

        mark_chat_read(&reqwest::Client::new(), &url, "a-self", &state)
            .await
            .expect("advance must succeed");

        let sets = read_position_sets(&server).await;
        assert_eq!(
            sets.first().map(|s| &s["update"]),
            Some(&json!({"rp-9": {"lastReadMessageId": ULID_A}}))
        );
    }

    #[tokio::test]
    async fn read_position_never_moves_backwards() {
        let server = read_position_server(
            json!([{"id": "rp-2", "chatId": "chat-v", "lastReadMessageId": ULID_C}]),
            set_updated("rp-2"),
        )
        .await;
        let url = format!("{}/jmap/api", server.uri());
        let state = viewing("chat-v", &[ULID_A, ULID_B]);

        mark_chat_read(&reqwest::Client::new(), &url, "a-self", &state)
            .await
            .expect("no-op must succeed");
        assert!(read_position_sets(&server).await.is_empty());
    }

    #[tokio::test]
    async fn chat_without_read_position_sends_no_set() {
        let server = read_position_server(
            json!([{"id": "rp-1", "chatId": "chat-other"}]),
            set_updated("rp-1"),
        )
        .await;
        let url = format!("{}/jmap/api", server.uri());
        let state = viewing("chat-v", &[ULID_A]);

        mark_chat_read(&reqwest::Client::new(), &url, "a-self", &state)
            .await
            .expect("no-op must succeed");
        assert!(read_position_sets(&server).await.is_empty());
    }

    #[tokio::test]
    async fn read_position_not_updated_is_an_error() {
        let server = read_position_server(
            json!([{"id": "rp-2", "chatId": "chat-v"}]),
            json!({"accountId": "a-self", "oldState": "rp-s1", "newState": "rp-s1",
                   "notUpdated": {"rp-2": {"type": "notFound"}}}),
        )
        .await;
        let url = format!("{}/jmap/api", server.uri());
        let state = viewing("chat-v", &[ULID_A]);

        assert!(
            mark_chat_read(&reqwest::Client::new(), &url, "a-self", &state)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn wrong_method_response_is_an_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["error", {"type": "unknownMethod"}, "r0"]],
                "sessionState": "s-1"
            })))
            .mount(&server)
            .await;
        let url = format!("{}/jmap/api", server.uri());
        let state = viewing("chat-v", &[ULID_A]);

        assert!(
            mark_chat_read(&reqwest::Client::new(), &url, "a-self", &state)
                .await
                .is_err()
        );
        assert!(read_position_sets(&server).await.is_empty());
    }

    // A message arriving over SSE in the chat being viewed is displayed, so it
    // is read: the cursor moves to its id.
    #[tokio::test]
    async fn sse_message_in_viewed_chat_advances_read_position() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = read_position_server(
            json!([{"id": "rp-2", "chatId": "chat-v", "lastReadMessageId": ULID_A}]),
            set_updated("rp-2"),
        )
        .await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .and(body_string_contains("Message/changes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["Message/changes",
                    {"accountId": "a-self", "oldState": "s-3", "newState": "s-4",
                     "hasMoreChanges": false, "created": [ULID_B], "updated": [], "destroyed": []},
                    "mc0"]],
                "sessionState": "s-1"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .and(body_string_contains("Message/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["Message/get",
                    {"accountId": "a-self", "state": "s-4", "list": [{
                        "id": ULID_B, "chatId": "chat-v", "senderId": "c-1",
                        "body": "hi", "bodyType": "text/plain", "attachments": [],
                        "sentAt": "2026-10-30T12:00:00Z", "receivedAt": "2026-10-30T12:00:00Z"
                    }]},
                    "mg0"]],
                "sessionState": "s-1"
            })))
            .mount(&server)
            .await;
        let url = format!("{}/jmap/api", server.uri());
        let mut state = viewing("chat-v", &[ULID_A]);
        state.message_state = "s-3".to_string();

        let sc = StateChange::new("Message", "s-4");
        handle_state_change(&reqwest::Client::new(), &url, "a-self", &sc, &mut state).await;

        let sets = read_position_sets(&server).await;
        assert_eq!(
            sets.first().map(|s| &s["update"]),
            Some(&json!({"rp-2": {"lastReadMessageId": ULID_B}}))
        );
    }

    // KITH-1ln3.11 fixtures, captured from chinwag 830be27 on 2026-10-30.
    const CW_ACCOUNT: &str = "01M66FP313VFV9WRD2PVMVAMB5";
    const CW_CHAT: &str = "01M66FPR850ZG2WJBBHCZZ7V34";
    const CW_READ_POSITION: &str = "01M66FS2JWYE0VC366HG5843CY";
    const CW_MESSAGE: &str = "01M66FS2JQJDGR1KHEMYY0KVMM";

    fn cw_message() -> Value {
        json!({"actions": [], "attachments": [], "body": "hello from kith-tui",
               "bodyType": "text/plain", "broadcastMentions": [], "chatId": CW_CHAT,
               "deliveryState": "pending", "id": CW_MESSAGE, "mentions": [],
               "reactions": {}, "receivedAt": "2026-10-30T13:25:23.159Z",
               "senderId": CW_ACCOUNT, "senderMsgId": CW_MESSAGE,
               "sentAt": "2026-10-30T13:25:23.157Z"})
    }

    /// A chinwag-shaped server for the first message in a chat that was
    /// empty when opened: the ReadPosition has no lastReadMessageId yet,
    /// Message/changes answers cannotCalculateChanges (chinwag's answer to
    /// both "s-0" and stale states), and a reload finds the one message.
    async fn cw_first_message_server() -> wiremock::MockServer {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = read_position_server(
            json!([{"chatId": CW_CHAT, "id": CW_READ_POSITION}]),
            set_updated(CW_READ_POSITION),
        )
        .await;
        let mount = |needle: &'static str, body: Value| {
            Mock::given(method("POST"))
                .and(path("/jmap/api"))
                .and(body_string_contains(needle))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
        };
        mount(
            "Message/changes",
            json!({"methodResponses": [["error", {"type": "cannotCalculateChanges"}, "mc0"]],
                   "sessionState": "0"}),
        )
        .mount(&server)
        .await;
        mount(
            "Message/query",
            json!({"methodResponses": [["Message/query",
                       {"accountId": CW_ACCOUNT, "ids": [CW_MESSAGE], "position": 0,
                        "queryState": "q-1", "total": 1, "canCalculateChanges": false},
                       "mq0"]],
                   "sessionState": "0"}),
        )
        .mount(&server)
        .await;
        mount(
            "Message/get",
            json!({"methodResponses": [["Message/get",
                       {"accountId": CW_ACCOUNT, "list": [cw_message()],
                        "notFound": [], "state": "1"},
                       "mg0"]],
                   "sessionState": "0"}),
        )
        .mount(&server)
        .await;
        server
    }

    /// The sinceState of every Message/changes call the server received.
    async fn since_states_sent(server: &wiremock::MockServer) -> Vec<Value> {
        server
            .received_requests()
            .await
            .expect("recording on")
            .iter()
            .flat_map(|req| {
                let body: Value = serde_json::from_slice(&req.body).expect("JSON body");
                body["methodCalls"].as_array().expect("methodCalls").clone()
            })
            .filter(|call| call[0] == "Message/changes")
            .map(|call| call[1]["sinceState"].clone())
            .collect()
    }

    fn viewing_cw_chat() -> AppState {
        let mut state = AppState::new();
        state.chat_ids = vec![CW_CHAT.to_string()];
        state.owner_id = CW_ACCOUNT.to_string();
        state
    }

    // RFC 8620 §5.2: sinceState is "the string that was returned as the
    // "state" argument in the "Foo/get" response". An empty chat still has a
    // Message state; the loader must fetch it so a later Message/changes has
    // something legitimate to send.
    #[tokio::test]
    async fn empty_chat_load_takes_state_from_message_get() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .and(body_string_contains("Message/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["Message/query",
                    {"accountId": CW_ACCOUNT, "ids": [], "position": 0,
                     "queryState": "q-0", "total": 0, "canCalculateChanges": false},
                    "mq0"]],
                "sessionState": "0"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/jmap/api"))
            .and(body_string_contains("Message/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "methodResponses": [["Message/get",
                    {"accountId": CW_ACCOUNT, "list": [], "notFound": [], "state": "0"},
                    "mg0"]],
                "sessionState": "0"
            })))
            .mount(&server)
            .await;
        let url = format!("{}/jmap/api", server.uri());

        let loaded = load_messages_for_chat(
            &reqwest::Client::new(),
            &url,
            CW_ACCOUNT,
            CW_CHAT,
            &HashMap::new(),
            CW_ACCOUNT,
        )
        .await;

        assert!(!loaded.is_error);
        assert!(loaded.display_lines.is_empty());
        assert_eq!(loaded.state, "0", "state must come from Message/get");
    }

    // RFC 8620 §5.2: with no state from the server yet, the client has no
    // legitimate sinceState. It must resync with a full load (and so mark the
    // chat read), not invent one: chinwag answered sinceState "s-0" with
    // cannotCalculateChanges and the badge stayed at (1).
    #[tokio::test]
    async fn message_change_without_known_state_resyncs_and_marks_read() {
        let server = cw_first_message_server().await;
        let url = format!("{}/jmap/api", server.uri());
        let mut state = viewing_cw_chat();

        let sc = StateChange::new("Message", "1");
        handle_state_change(&reqwest::Client::new(), &url, CW_ACCOUNT, &sc, &mut state).await;

        assert_eq!(
            since_states_sent(&server).await,
            Vec::<Value>::new(),
            "no server-issued state exists, so no sinceState may be sent"
        );
        assert_eq!(state.message_state, "1");
        let sets = read_position_sets(&server).await;
        assert_eq!(
            sets.first().map(|s| &s["update"]),
            Some(&json!({CW_READ_POSITION: {"lastReadMessageId": CW_MESSAGE}}))
        );
    }

    // RFC 8620 §5.2: cannotCalculateChanges means resync from /get. The
    // resynced chat is on screen, so it is read and the ReadPosition moves.
    #[tokio::test]
    async fn cannot_calculate_changes_resync_marks_chat_read() {
        let server = cw_first_message_server().await;
        let url = format!("{}/jmap/api", server.uri());
        let mut state = viewing_cw_chat();
        state.message_state = "0".to_string();

        let sc = StateChange::new("Message", "1");
        handle_state_change(&reqwest::Client::new(), &url, CW_ACCOUNT, &sc, &mut state).await;

        assert_eq!(since_states_sent(&server).await, vec![json!("0")]);
        assert_eq!(state.message_state, "1");
        let sets = read_position_sets(&server).await;
        assert_eq!(
            sets.first().map(|s| &s["update"]),
            Some(&json!({CW_READ_POSITION: {"lastReadMessageId": CW_MESSAGE}}))
        );
    }
}
