use std::io::Cursor;

use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    ClipboardMessageType, MessageEnvelope, MessageType, ProtocolLimitError, ProtocolLimits,
    read_json_frame,
};

const VALID_ENVELOPE: &str = r#"{"v":1,"id":"message-1","t":"clipboard.text","sid":"session-1","seq":1,"ts":1792700000000,"body":{"text":"hello"}}"#;

#[derive(Debug, Deserialize)]
struct ClipboardTextBody {
    text: String,
}

fn default_limits() -> ProtocolLimits {
    ProtocolLimits::default()
}

#[test]
fn malformed_vectors_reject_missing_required_fields() {
    let cases = [
        r#"{"v":1,"id":"message-1","t":"clipboard.text","seq":1,"ts":1792700000000,"body":{}}"#,
        r#"{"v":1,"id":"message-1","t":"clipboard.text","sid":"session-1","ts":1792700000000,"body":{}}"#,
        r#"{"v":1,"id":"message-1","t":"clipboard.text","sid":"session-1","seq":1,"ts":1792700000000}"#,
    ];

    for payload in cases {
        let result = serde_json::from_str::<MessageEnvelope<Value>>(payload);
        assert!(
            result.is_err(),
            "malformed payload unexpectedly decoded: {payload}"
        );
    }
}

#[test]
fn malformed_vectors_reject_wrong_field_types() {
    let cases = [
        r#"{"v":"1","id":"message-1","t":"clipboard.text","sid":"session-1","seq":1,"ts":1792700000000,"body":{}}"#,
        r#"{"v":1,"id":7,"t":"clipboard.text","sid":"session-1","seq":1,"ts":1792700000000,"body":{}}"#,
        r#"{"v":1,"id":"message-1","t":false,"sid":"session-1","seq":1,"ts":1792700000000,"body":{}}"#,
        r#"{"v":1,"id":"message-1","t":"clipboard.text","sid":"session-1","seq":"1","ts":1792700000000,"body":{}}"#,
    ];

    for payload in cases {
        let result = serde_json::from_str::<MessageEnvelope<Value>>(payload);
        assert!(
            result.is_err(),
            "wrong-type payload unexpectedly decoded: {payload}"
        );
    }

    let array_body = r#"{"v":1,"id":"message-1","t":"clipboard.text","sid":"session-1","seq":1,"ts":1792700000000,"body":[]}"#;
    let result = serde_json::from_str::<MessageEnvelope<ClipboardTextBody>>(array_body);
    assert!(
        result.is_err(),
        "array body unexpectedly decoded as clipboard body"
    );
}

#[test]
fn malformed_vectors_reject_invalid_json_inside_a_frame() {
    let mut frame = Vec::new();
    framed_ipc::write_frame(
        &mut frame,
        br#"{"v":1,"id":"message-1""#,
        framed_ipc::FrameLimits::new(256).expect("frame limits should be valid"),
    )
    .expect("malformed JSON frame should be writable");

    let result =
        read_json_frame::<_, MessageEnvelope<Value>>(&mut Cursor::new(frame), default_limits());

    assert!(result.is_err());
}

#[test]
fn malformed_vectors_reject_oversized_json_data_before_writing() {
    let limits = ProtocolLimits::new(128, 32, 64, 8, 64);
    let payload = json!({ "text": "this body exceeds the JSON budget" });
    let mut output = Vec::new();

    let error = super::write_json_frame(&mut output, &payload, limits)
        .expect_err("oversized JSON should be rejected")
        .to_string();

    assert!(error.contains("protocol JSON is too large"));
    assert!(output.is_empty());
}

#[test]
fn malformed_vectors_reject_empty_and_whitespace_identifiers() {
    for invalid_id in ["", "   "] {
        let envelope: MessageEnvelope<Value> =
            serde_json::from_str(&VALID_ENVELOPE.replace("message-1", invalid_id))
                .expect("shape-valid payload should decode before semantic validation");

        let error = envelope
            .validate_limits(default_limits())
            .expect_err("empty identifier should fail semantic validation")
            .downcast_inner::<ProtocolLimitError>()
            .expect("protocol limit error should be preserved");

        assert_eq!(error, ProtocolLimitError::InvalidIdentifier { field: "id" });
    }
}

#[test]
fn malformed_vectors_keep_known_message_type_validation() {
    let envelope: MessageEnvelope<Value> =
        serde_json::from_str(VALID_ENVELOPE).expect("valid envelope should decode");

    assert_eq!(
        envelope.message_type,
        MessageType::Clipboard(ClipboardMessageType::Text)
    );
}
