use serde::{Deserialize, Serialize};

/// A reference to the result of a previous invocation in the same JMAP request batch.
/// Used in method arguments with a "#" prefix on the JSON key (RFC 8620 §9).
///
/// Example JSON:
/// ```json
/// {"resultOf": "0", "name": "ChatContact/get", "path": "/list/0/id"}
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultReference {
    /// The call-id of the prior method invocation being referenced.
    #[serde(rename = "resultOf")]
    pub result_of: String,
    /// The method name of that prior invocation (e.g. "ChatContact/get").
    pub name: String,
    /// JSON Pointer (RFC 6901) into the result, e.g. "/list/0/id".
    pub path: String,
}

/// A JMAP method argument that can be either a direct value or a ResultReference.
///
/// In JMAP JSON, a ResultReference is indicated by a "#" prefix on the key:
///   `"ids": [...]`  →  Argument::Value([...])
///   `"#ids": {...}` →  Argument::Ref(ResultReference { ... })
///
/// The resolver in kith-jmap evaluates Ref variants before method dispatch.
///
/// # Deserialization note
/// Uses `#[serde(untagged)]` which tries to deserialize as T first.
/// If T and ResultReference share field names, T is preferred.
/// Callers must handle the `#` key prefix before deserializing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Argument<T> {
    Value(T),
    Ref(ResultReference),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_reference_round_trip() {
        // Independent oracle: RFC 8620 §9 example
        let rr = ResultReference {
            result_of: "0".into(),
            name: "ChatContact/get".into(),
            path: "/list/0/id".into(),
        };
        let json_str = serde_json::to_string(&rr).unwrap();
        let rr2: ResultReference = serde_json::from_str(&json_str).unwrap();
        assert_eq!(rr, rr2);
    }

    #[test]
    fn result_reference_field_names() {
        let rr = ResultReference {
            result_of: "req-1".into(),
            name: "Chat/get".into(),
            path: "/id".into(),
        };
        let json_str = serde_json::to_string(&rr).unwrap();
        assert!(
            json_str.contains("\"resultOf\""),
            "must use camelCase resultOf"
        );
        assert!(json_str.contains("\"name\""));
        assert!(json_str.contains("\"path\""));
        assert!(
            !json_str.contains("\"result_of\""),
            "must not use snake_case"
        );
    }

    #[test]
    fn argument_value_serializes_as_inner_type() {
        let arg: Argument<u32> = Argument::Value(42);
        let json_str = serde_json::to_string(&arg).unwrap();
        assert_eq!(json_str, "42");
    }

    #[test]
    fn argument_ref_serializes_as_result_reference() {
        let rr = ResultReference {
            result_of: "0".into(),
            name: "ChatContact/get".into(),
            path: "/list/0/id".into(),
        };
        let arg: Argument<Vec<String>> = Argument::Ref(rr);
        let json_str = serde_json::to_string(&arg).unwrap();
        assert!(json_str.contains("\"resultOf\""));
        assert!(json_str.contains("\"ChatContact/get\""));
    }

    #[test]
    fn argument_value_vec_string_deserializes() {
        let json_str = r#"["alice","bob"]"#;
        let arg: Argument<Vec<String>> = serde_json::from_str(json_str).unwrap();
        match arg {
            Argument::Value(v) => assert_eq!(v, vec!["alice", "bob"]),
            Argument::Ref(_) => panic!("expected Value variant"),
        }
    }
}
