use std::io::Cursor;

use serde_json::json;

use peerbay_lib::protocol::{
    ClipboardMessageType, MessageEnvelope, MessageType, PROTOCOL_VERSION, ProtocolLimits,
    read_json_frame, write_json_frame,
};

fn test_limits() -> ProtocolLimits {
    ProtocolLimits::new(256, 128, 64, 8, 128)
}

#[test]
fn json_frames_roundtrip_a_versioned_envelope() {
    let original = MessageEnvelope::new(
        "message-1",
        MessageType::Clipboard(ClipboardMessageType::Text),
        "session-1",
        3,
        1_792_700_000_000,
        json!({ "text": "hello" }),
    );
    let mut bytes = Vec::new();

    write_json_frame(&mut bytes, &original, test_limits()).expect("frame should be written");
    let payload_length = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .expect("JSON frame should have a four-byte header"),
    ) as usize;
    assert_eq!(payload_length, bytes.len() - 4);

    let decoded: MessageEnvelope<serde_json::Value> =
        read_json_frame(&mut Cursor::new(bytes), test_limits()).expect("frame should be read");

    assert_eq!(decoded.v, PROTOCOL_VERSION);
    assert_eq!(decoded, original);
}

#[test]
fn json_frames_reject_payloads_over_the_protocol_budget() {
    let limits = ProtocolLimits::new(64, 16, 64, 8, 16);
    let value = json!({ "text": "this payload is too large" });
    let mut bytes = Vec::new();

    let error = write_json_frame(&mut bytes, &value, limits)
        .expect_err("oversized JSON should be rejected")
        .to_string();

    assert!(error.contains("protocol JSON is too large") || error.contains("protocol payload"));
    assert!(bytes.is_empty());
}

#[test]
fn json_frames_reject_malformed_payloads() {
    let mut bytes = Vec::new();
    framed_ipc::write_frame(
        &mut bytes,
        br#"{"v":1,"id":"broken""#,
        framed_ipc::FrameLimits::new(128).expect("frame limits should be valid"),
    )
    .expect("malformed frame should still be writable");

    let result = read_json_frame::<_, serde_json::Value>(&mut Cursor::new(bytes), test_limits());

    assert!(result.is_err());
}
