use serde_json::json;

use peerbay_lib::protocol::{
    ClipboardMessageType, ControlMessageType, MessageEnvelope, MessageType, PROTOCOL_VERSION,
};

#[test]
fn envelope_serializes_the_versioned_wire_fields() {
    let envelope = MessageEnvelope::new(
        "message-uuid",
        MessageType::Clipboard(ClipboardMessageType::Text),
        "session-id",
        42,
        1_792_700_000_000,
        json!({ "text": "hello" }),
    );

    let value = serde_json::to_value(&envelope).expect("envelope should serialize");

    assert_eq!(value["v"], PROTOCOL_VERSION);
    assert_eq!(value["id"], "message-uuid");
    assert_eq!(value["t"], "clipboard.text");
    assert_eq!(value["sid"], "session-id");
    assert_eq!(value["seq"], 42);
    assert_eq!(value["ts"], 1_792_700_000_000u64);
    assert_eq!(value["body"]["text"], "hello");
}

#[test]
fn envelope_roundtrips_without_changing_the_body() {
    let original = MessageEnvelope::new(
        "message-uuid",
        MessageType::Control(ControlMessageType::Ping),
        "session-id",
        7,
        1_792_700_000_001,
        json!({ "nonce": 3, "ack": true }),
    );

    let encoded = serde_json::to_string(&original).expect("envelope should serialize");
    let decoded: MessageEnvelope<serde_json::Value> =
        serde_json::from_str(&encoded).expect("envelope should deserialize");

    assert_eq!(decoded, original);
}
