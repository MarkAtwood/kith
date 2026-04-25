use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// RFC 3339 UTC timestamp string, e.g. "2026-04-18T20:14:00Z".
/// Used for all date/time fields in JMAP responses.
pub type UTCDate = String;

/// Opaque non-empty string identifier (server-assigned).
pub type Id = String;

/// A JMAP method invocation: [method_name, arguments, call_id].
/// Serializes as a 3-element JSON array per RFC 8620 §3.2.
pub type Invocation = (String, serde_json::Value, String);

/// JMAP request envelope (RFC 8620 §3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JmapRequest {
    /// Capability URIs this request uses, e.g. ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"].
    pub using: Vec<String>,
    /// Ordered list of method invocations.
    #[serde(rename = "methodCalls")]
    pub method_calls: Vec<Invocation>,
}

/// JMAP response envelope (RFC 8620 §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JmapResponse {
    /// Ordered list of method responses (same 3-tuple structure as requests).
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<Invocation>,
    /// Opaque server state token. Changes when any data type's state advances.
    #[serde(rename = "sessionState")]
    pub session_state: String,
    /// Maps client-supplied creation IDs to server-assigned IDs, accumulated
    /// across all /set calls in the batch (RFC 8620 §3.4).
    /// Omitted when no objects were created in the batch.
    #[serde(rename = "createdIds", skip_serializing_if = "Option::is_none")]
    pub created_ids: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jmap_request_round_trip() {
        let req = JmapRequest {
            using: vec![
                "urn:ietf:params:jmap:core".into(),
                "urn:ietf:params:jmap:chat".into(),
            ],
            method_calls: vec![
                (
                    "ChatContact/get".into(),
                    json!({"accountId": "a-self"}),
                    "0".into(),
                ),
                (
                    "Chat/get".into(),
                    json!({"accountId": "a-self", "ids": ["chat-1"]}),
                    "1".into(),
                ),
            ],
        };
        let json_str = serde_json::to_string(&req).unwrap();
        let req2: JmapRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(req.using, req2.using);
        assert_eq!(req.method_calls.len(), req2.method_calls.len());
        assert_eq!(req.method_calls[0].0, req2.method_calls[0].0);
        assert_eq!(req.method_calls[0].2, req2.method_calls[0].2);
    }

    #[test]
    fn jmap_request_uses_camel_case_field() {
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:core".into()],
            method_calls: vec![],
        };
        let json_str = serde_json::to_string(&req).unwrap();
        assert!(
            json_str.contains("\"methodCalls\""),
            "must use camelCase 'methodCalls'"
        );
        assert!(
            !json_str.contains("\"method_calls\""),
            "must not use snake_case"
        );
    }

    #[test]
    fn jmap_response_round_trip() {
        let resp = JmapResponse {
            method_responses: vec![(
                "ChatContact/get".into(),
                json!({"list": [], "state": "s-1"}),
                "0".into(),
            )],
            session_state: "s-42".into(),
            created_ids: None,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(json_str.contains("\"methodResponses\""));
        assert!(json_str.contains("\"sessionState\""));
        let resp2: JmapResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(resp.session_state, resp2.session_state);
    }

    // Oracle: RFC 8620 §3.4 — createdIds maps client-supplied IDs to server-assigned IDs.
    // When objects are created in /set calls, the response MUST include createdIds.
    // When no objects are created, the field MUST be omitted.
    #[test]
    fn jmap_response_created_ids_present_when_set() {
        let mut ids = HashMap::new();
        ids.insert("c0".to_string(), "server-id-1".to_string());
        let resp = JmapResponse {
            method_responses: vec![],
            session_state: "s-1".into(),
            created_ids: Some(ids),
        };
        let json_val = serde_json::to_value(&resp).unwrap();
        // RFC 8620 §3.4: createdIds must appear in JSON when Some
        let created_ids = json_val
            .get("createdIds")
            .expect("createdIds must be present");
        assert_eq!(created_ids["c0"], "server-id-1");
    }

    #[test]
    fn jmap_response_created_ids_absent_when_none() {
        let resp = JmapResponse {
            method_responses: vec![],
            session_state: "s-1".into(),
            created_ids: None,
        };
        let json_val = serde_json::to_value(&resp).unwrap();
        // RFC 8620 §3.4: createdIds may be omitted when no objects were created
        assert!(
            json_val.get("createdIds").is_none(),
            "createdIds must be absent when None; got: {json_val}"
        );
    }

    #[test]
    fn invocation_is_three_element_array() {
        let inv: Invocation = ("ChatContact/get".into(), json!({}), "req-0".into());
        let json_str = serde_json::to_string(&inv).unwrap();
        // Must serialize as ["ChatContact/get", {}, "req-0"]
        assert_eq!(json_str, r#"["ChatContact/get",{},"req-0"]"#);
    }
}
