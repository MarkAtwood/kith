use serde::{Deserialize, Serialize};

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
    /// Capability URIs this request uses, e.g. ["urn:ietf:params:jmap:core", "urn:kith:chat:1"].
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jmap_request_round_trip() {
        let req = JmapRequest {
            using: vec!["urn:ietf:params:jmap:core".into(), "urn:kith:chat:1".into()],
            method_calls: vec![
                (
                    "Contact/get".into(),
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
                "Contact/get".into(),
                json!({"list": [], "state": "s-1"}),
                "0".into(),
            )],
            session_state: "s-42".into(),
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(json_str.contains("\"methodResponses\""));
        assert!(json_str.contains("\"sessionState\""));
        let resp2: JmapResponse = serde_json::from_str(&json_str).unwrap();
        assert_eq!(resp.session_state, resp2.session_state);
    }

    #[test]
    fn invocation_is_three_element_array() {
        let inv: Invocation = ("Contact/get".into(), json!({}), "req-0".into());
        let json_str = serde_json::to_string(&inv).unwrap();
        // Must serialize as ["Contact/get", {}, "req-0"]
        assert_eq!(json_str, r#"["Contact/get",{},"req-0"]"#);
    }
}
