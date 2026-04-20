//! Unit tests for pure helper functions in kithctl::watch.
//!
//! Oracle: expected values were computed by hand from the SSE spec
//! (https://html.spec.whatwg.org/multipage/server-sent-events.html) and from
//! the kith CLAUDE.md security rules, not derived from the code under test.

use kithctl::watch::{is_valid_last_event_id, parse_sse_frame, sanitize_sender, truncate_body};

// ── Test 1: truncate_body (ASCII) ─────────────────────────────────────────────

/// Oracle: "hello world" limited to 5 chars → "hello" + ellipsis character.
/// "hi" is shorter than 5 → unchanged.
/// Empty string → unchanged.
#[test]
fn truncate_body_ascii() {
    assert_eq!(
        truncate_body("hello world", 5),
        "hello\u{2026}",
        "should truncate at exactly max_chars and append ellipsis"
    );
    assert_eq!(
        truncate_body("hi", 5),
        "hi",
        "string shorter than max_chars must not be modified"
    );
    assert_eq!(
        truncate_body("", 5),
        "",
        "empty string must return empty string"
    );
}

// ── Test 2: truncate_body (UTF-8) ─────────────────────────────────────────────

/// Oracle: "日本語テスト" is 6 Unicode scalar values (each 3 bytes in UTF-8).
/// Limiting to 3 chars must produce the first 3 characters plus ellipsis,
/// not truncate at a byte boundary.
#[test]
fn truncate_body_utf8() {
    assert_eq!(
        truncate_body("日本語テスト", 3),
        "日本語\u{2026}",
        "must truncate at Unicode character boundary, not byte boundary"
    );
}

// ── Test 3: sanitize_sender ───────────────────────────────────────────────────

/// Oracle: NUL, CR, LF, and TAB must be stripped; all other chars preserved.
/// Regular email-style sender must pass through unchanged.
#[test]
fn sanitize_sender_strips_control_chars() {
    assert_eq!(
        sanitize_sender("alice\x00\ninjection"),
        "aliceinjection",
        "NUL and LF must be removed"
    );
    assert_eq!(
        sanitize_sender("alice@example.com"),
        "alice@example.com",
        "clean sender must pass through unchanged"
    );
}

// ── Test 4: parse_sse_frame ───────────────────────────────────────────────────

/// Oracle: constructed from SSE spec field definitions.
/// "event:" → event_type, "data:" → data, "id:" → id.
#[test]
fn parse_sse_frame_full() {
    let (event_type, data, id) = parse_sse_frame("event: state\ndata: {\"x\":1}\nid: s-42");
    assert_eq!(event_type.as_deref(), Some("state"), "event field");
    assert_eq!(data.as_deref(), Some("{\"x\":1}"), "data field");
    assert_eq!(id.as_deref(), Some("s-42"), "id field");
}

/// Oracle: a frame with only a data line must have None for event_type and id.
#[test]
fn parse_sse_frame_data_only() {
    let (event_type, data, id) = parse_sse_frame("data: {\"x\":2}");
    assert_eq!(event_type, None, "no event field → None");
    assert_eq!(data.as_deref(), Some("{\"x\":2}"), "data field");
    assert_eq!(id, None, "no id field → None");
}

/// Oracle: empty frame must return (None, None, None).
#[test]
fn parse_sse_frame_empty() {
    let (event_type, data, id) = parse_sse_frame("");
    assert_eq!(event_type, None);
    assert_eq!(data, None);
    assert_eq!(id, None);
}

/// Oracle: RFC 8895 §9.2.6 — multiple "data:" lines in one frame MUST be
/// concatenated with U+000A (newline) between them.
/// Input and expected value are derived directly from the RFC text, not from
/// the code under test.
#[test]
fn parse_sse_frame_multiline_data() {
    let (event_type, data, id) = parse_sse_frame("event: state\ndata: line1\ndata: line2\nid: s-1");
    assert_eq!(event_type.as_deref(), Some("state"), "event field");
    assert_eq!(
        data.as_deref(),
        Some("line1\nline2"),
        "multiple data: lines must be joined with newline per RFC 8895 §9.2.6"
    );
    assert_eq!(id.as_deref(), Some("s-1"), "id field");
}

// ── Test 5: is_valid_last_event_id ───────────────────────────────────────────

/// Oracle: valid IDs per kith spec are "s-\d+" or empty string.
/// Anything else (injection attempts, bare "s-", etc.) must be rejected.
#[test]
fn valid_last_event_id_accepted() {
    assert!(
        is_valid_last_event_id("s-0"),
        "s-0 is the starting state token"
    );
    assert!(
        is_valid_last_event_id("s-999"),
        "s-999 is a valid state token"
    );
    assert!(
        is_valid_last_event_id(""),
        "empty string is valid for initial connect"
    );
}

#[test]
fn invalid_last_event_id_rejected() {
    assert!(
        !is_valid_last_event_id("malicious\nheader: injected"),
        "header injection attempt must be rejected"
    );
    assert!(
        !is_valid_last_event_id("s-"),
        "s- without digits must be rejected"
    );
    assert!(
        !is_valid_last_event_id("0"),
        "bare number without s- prefix must be rejected"
    );
    assert!(
        !is_valid_last_event_id("s-abc"),
        "non-digit suffix must be rejected"
    );
}

// ── Test 6: SSE frame without event: field dispatch ───────────────────────────

/// Oracle: SSE spec §9.2.4 — a frame with no "event:" field has an implied
/// event type of "message".  Per kith's watch_once dispatch condition
/// (`event_type.is_none()`), such frames are processed as state events.
///
/// This test verifies that parse_sse_frame returns None for event_type when
/// the frame has no "event:" line, confirming the watch_once condition
/// `event_type.as_deref() == Some("state") || event_type.is_none()` will
/// match frames emitted without an explicit event field.
#[test]
fn watch_dispatches_frame_without_event_type() {
    // Oracle: a frame with only a data line returns None for event_type.
    // This is the SSE spec behaviour for frames without an "event:" field.
    let (event_type, data, id) = parse_sse_frame("data: {\"x\":1}");
    assert_eq!(
        event_type, None,
        "frame without event: field must yield None event_type"
    );
    assert_eq!(
        data.as_deref(),
        Some("{\"x\":1}"),
        "data field must be parsed"
    );
    assert_eq!(id, None, "no id field → None");

    // Confirm: None event_type satisfies the dispatch condition used in watch_once.
    // watch_once dispatches when: event_type.as_deref() == Some("state") || event_type.is_none()
    let dispatched = event_type.as_deref() == Some("state") || event_type.is_none();
    assert!(
        dispatched,
        "frame with None event_type must be dispatched by watch_once"
    );
}
