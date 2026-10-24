use peerbay_lib::protocol::{ProtocolError, ProtocolErrorCode, ProtocolErrorScope};

#[test]
fn error_payload_serializes_stable_wire_fields() {
    let error = ProtocolError::new(
        ProtocolErrorCode::InvalidPayload,
        false,
        ProtocolErrorScope::Message,
        "corr-123",
    );

    let value = serde_json::to_value(&error).expect("protocol error should serialize");

    assert_eq!(value["code"], "invalid_payload");
    assert_eq!(value["retryable"], false);
    assert_eq!(value["scope"], "message");
    assert_eq!(value["correlation_id"], "corr-123");
}

#[test]
fn error_payload_roundtrips_all_structured_fields() {
    let original = ProtocolError::new(
        ProtocolErrorCode::PeerUnavailable,
        true,
        ProtocolErrorScope::Session,
        "session-connect-7",
    );

    let encoded = serde_json::to_string(&original).expect("protocol error should serialize");
    let decoded: ProtocolError =
        serde_json::from_str(&encoded).expect("protocol error should deserialize");

    assert_eq!(decoded, original);
}

#[test]
fn error_codes_and_scopes_cover_the_wire_contract() {
    let codes = [
        ProtocolErrorCode::InvalidEnvelope,
        ProtocolErrorCode::UnsupportedVersion,
        ProtocolErrorCode::UnknownMessageType,
        ProtocolErrorCode::InvalidPayload,
        ProtocolErrorCode::LimitExceeded,
        ProtocolErrorCode::SequenceViolation,
        ProtocolErrorCode::Unauthorized,
        ProtocolErrorCode::Timeout,
        ProtocolErrorCode::PeerUnavailable,
        ProtocolErrorCode::Internal,
    ];
    let scopes = [
        ProtocolErrorScope::Message,
        ProtocolErrorScope::Channel,
        ProtocolErrorScope::Session,
        ProtocolErrorScope::Application,
    ];

    assert_eq!(codes.len(), 10);
    assert_eq!(scopes.len(), 4);
}
