use peerbay_lib::protocol::{
    ControlMessageType, DEFAULT_MAX_BATCH_ITEMS, DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_JSON_SIZE,
    DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_MAX_STRING_LENGTH, MessageEnvelope, MessageType,
    ProtocolLimitError, ProtocolLimits,
};

#[test]
fn default_limits_match_the_protocol_budget() {
    let limits = ProtocolLimits::default();

    assert_eq!(limits.max_frame_size(), DEFAULT_MAX_FRAME_SIZE);
    assert_eq!(limits.max_json_size(), DEFAULT_MAX_JSON_SIZE);
    assert_eq!(limits.max_string_length(), DEFAULT_MAX_STRING_LENGTH);
    assert_eq!(limits.max_batch_items(), DEFAULT_MAX_BATCH_ITEMS);
    assert_eq!(limits.max_payload_size(), DEFAULT_MAX_PAYLOAD_SIZE);
}

#[test]
fn limits_accept_the_boundary_and_reject_the_next_byte_or_item() {
    let limits = ProtocolLimits::new(4, 4, 4, 2, 4);

    limits
        .validate_frame_size(4)
        .expect("frame boundary is valid");
    limits
        .validate_json_size(4)
        .expect("JSON boundary is valid");
    limits
        .validate_string("name", "1234")
        .expect("string boundary is valid");
    limits
        .validate_batch("items", 2)
        .expect("batch boundary is valid");
    limits
        .validate_payload_size(4)
        .expect("payload boundary is valid");

    assert!(limits.validate_frame_size(5).is_err());
    assert!(limits.validate_json_size(5).is_err());
    assert!(limits.validate_string("name", "12345").is_err());
    assert!(limits.validate_batch("items", 3).is_err());
    assert!(limits.validate_payload_size(5).is_err());
}

#[test]
fn envelope_limit_validation_covers_wire_string_fields() {
    let limits = ProtocolLimits::new(64, 64, 4, 2, 32);
    let envelope = MessageEnvelope::new(
        "12345",
        MessageType::Control(ControlMessageType::Ping),
        "sid",
        1,
        2,
        (),
    );

    let error = envelope
        .validate_limits(limits)
        .expect_err("oversized message ID must be rejected")
        .downcast_inner::<ProtocolLimitError>()
        .expect("limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::StringTooLong {
            field: "id",
            length: 5,
            max: 4,
        }
    );
}
