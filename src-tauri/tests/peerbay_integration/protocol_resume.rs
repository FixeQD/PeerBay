use serde_json::json;

use peerbay_lib::protocol::{
    ChannelMigration, ChannelResumeCursor, ControlMessageType, MessageEnvelope, MessageType,
    ProtocolLimitError, ResumeError, ResumeKey, ResumeRejectionReason, SessionChannel,
    SessionResumeAccepted, SessionResumeRejected, SessionResumeRequest,
};

const SESSION_ID: &str = "session-01";
const RESUME_KEY_VALUE: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn resume_key() -> ResumeKey {
    ResumeKey::new(RESUME_KEY_VALUE).expect("resume key fixture should be valid")
}

fn migration() -> ChannelMigration {
    ChannelMigration::new(
        SessionChannel::Control,
        "control-old",
        "control-new",
        "local_network",
        "usb_adb",
    )
    .expect("migration fixture should be valid")
}

fn cursors() -> Vec<ChannelResumeCursor> {
    vec![
        ChannelResumeCursor::new(SessionChannel::Control, 20, 21),
        ChannelResumeCursor::new(SessionChannel::Bulk, 8, 9),
    ]
}

fn request() -> SessionResumeRequest {
    SessionResumeRequest::new(SESSION_ID, resume_key(), migration(), cursors(), 100, 200)
        .expect("resume request fixture should be valid")
}

fn resume_error(result: eros::Result<()>) -> ResumeError {
    result
        .expect_err("resume validation should fail")
        .downcast_inner::<ResumeError>()
        .expect("resume error should be preserved")
}

#[test]
fn session_resume_identifier_is_mapped_to_the_control_channel() {
    let message = MessageType::Control(ControlMessageType::SessionResume);

    assert_eq!(message.as_str(), "session.resume");
    assert_eq!(
        serde_json::to_string(&message).expect("identifier should serialize"),
        "\"session.resume\""
    );
}

#[test]
fn resume_key_is_serialized_as_canonical_lowercase_hex() {
    let value = serde_json::to_value(resume_key()).expect("resume key should serialize");

    assert_eq!(value, RESUME_KEY_VALUE);
}

#[test]
fn resume_key_debug_output_is_redacted() {
    let key = resume_key();
    let debug = format!("{key:?}");

    assert_eq!(debug, "ResumeKey(<redacted>)");
    assert!(!debug.contains(RESUME_KEY_VALUE));
}

#[test]
fn resume_key_roundtrips_through_json_without_changing_the_secret() {
    let encoded = serde_json::to_string(&resume_key()).expect("resume key should serialize");
    let decoded: ResumeKey = serde_json::from_str(&encoded).expect("resume key should deserialize");

    assert_eq!(decoded.as_str(), RESUME_KEY_VALUE);
}

#[test]
fn resume_key_rejects_short_long_uppercase_and_non_hex_values() {
    for value in [
        "",
        "abc",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890",
        "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
        "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
    ] {
        assert!(
            ResumeKey::new(value).is_err(),
            "invalid key was accepted: {value:?}"
        );
    }
}

#[test]
fn resume_key_deserialization_rejects_non_string_json_values() {
    for value in [
        json!(null),
        json!(123),
        json!(true),
        json!([RESUME_KEY_VALUE]),
    ] {
        assert!(
            serde_json::from_value::<ResumeKey>(value).is_err(),
            "non-string resume key was accepted"
        );
    }
}

#[test]
fn migration_serializes_channel_and_transport_transition() {
    let value = serde_json::to_value(migration()).expect("migration should serialize");

    assert_eq!(value["channel"], "control");
    assert_eq!(value["old_channel_id"], "control-old");
    assert_eq!(value["new_channel_id"], "control-new");
    assert_eq!(value["from_transport"], "local_network");
    assert_eq!(value["to_transport"], "usb_adb");
}

#[test]
fn all_session_channels_have_stable_wire_names() {
    let channels = [
        (SessionChannel::Control, "control"),
        (SessionChannel::Bulk, "bulk"),
        (SessionChannel::Media, "media"),
        (SessionChannel::Input, "input"),
        (SessionChannel::Fallback, "fallback"),
    ];

    for (channel, wire_name) in channels {
        assert_eq!(
            serde_json::to_string(&channel).expect("channel should serialize"),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn migration_rejects_reusing_the_old_channel_id() {
    let error = ChannelMigration {
        old_channel_id: "same".to_owned(),
        new_channel_id: "same".to_owned(),
        ..migration()
    }
    .validate()
    .map(|_| ())
    .map_err(|error| error)
    .expect_err("migration must allocate a new channel ID")
    .downcast_inner::<ResumeError>()
    .expect("resume error should be preserved");

    assert_eq!(error, ResumeError::SameChannelId);
}

#[test]
fn migration_rejects_a_transport_that_did_not_change() {
    let error = ChannelMigration {
        to_transport: "local_network".to_owned(),
        ..migration()
    }
    .validate()
    .expect_err("migration must change physical transport")
    .downcast_inner::<ResumeError>()
    .expect("resume error should be preserved");

    assert_eq!(error, ResumeError::SameTransport);
}

#[test]
fn migration_rejects_path_like_and_control_character_identifiers() {
    let path = ChannelMigration {
        old_channel_id: "../../old".to_owned(),
        ..migration()
    };
    assert_eq!(
        resume_error(path.validate()),
        ResumeError::InvalidIdentifierCharacter {
            field: "old_channel_id"
        }
    );

    let control = ChannelMigration {
        to_transport: "usb\nadb".to_owned(),
        ..migration()
    };
    assert_eq!(
        resume_error(control.validate()),
        ResumeError::ControlCharacter {
            field: "to_transport"
        }
    );
}

#[test]
fn request_serializes_resume_key_only_on_the_request_wire_shape() {
    let value = serde_json::to_value(request()).expect("request should serialize");

    assert_eq!(value["session_id"], SESSION_ID);
    assert_eq!(value["resume_key"], RESUME_KEY_VALUE);
    assert_eq!(value["migration"]["new_channel_id"], "control-new");
    assert_eq!(value["cursors"][0]["last_received_seq"], 20);
    assert_eq!(value["requested_at_ms"], 100);
    assert_eq!(value["expires_at_ms"], 200);
}

#[test]
fn request_roundtrips_inside_the_versioned_session_resume_envelope() {
    let envelope = MessageEnvelope::new(
        "resume-message-1",
        MessageType::Control(ControlMessageType::SessionResume),
        SESSION_ID,
        30,
        101,
        request(),
    );

    let encoded = serde_json::to_string(&envelope).expect("resume envelope should serialize");
    let decoded: MessageEnvelope<SessionResumeRequest> =
        serde_json::from_str(&encoded).expect("resume envelope should deserialize");

    assert_eq!(decoded, envelope);
    assert_eq!(decoded.message_type.as_str(), "session.resume");
}

#[test]
fn request_must_match_the_envelope_session_id() {
    let error = request()
        .validate_for_session("different-session")
        .expect_err("resume must be bound to the envelope session")
        .downcast_inner::<ResumeError>()
        .expect("resume error should be preserved");

    assert_eq!(
        error,
        ResumeError::SessionMismatch {
            expected: "different-session".to_owned(),
            received: SESSION_ID.to_owned(),
        }
    );
}

#[test]
fn request_accepts_the_matching_envelope_session_id() {
    request()
        .validate_for_session(SESSION_ID)
        .expect("matching session ID should be accepted");
}

#[test]
fn request_rejects_an_empty_cursor_list() {
    let error = SessionResumeRequest {
        cursors: Vec::new(),
        ..request()
    };

    assert_eq!(resume_error(error.validate()), ResumeError::EmptyCursors);
}

#[test]
fn request_rejects_duplicate_channel_cursors() {
    let error = SessionResumeRequest {
        cursors: vec![
            ChannelResumeCursor::new(SessionChannel::Control, 1, 1),
            ChannelResumeCursor::new(SessionChannel::Control, 2, 2),
        ],
        ..request()
    };

    assert_eq!(
        resume_error(error.validate()),
        ResumeError::DuplicateChannel {
            channel: SessionChannel::Control,
        }
    );
}

#[test]
fn request_rejects_a_cursor_batch_over_the_protocol_limit() {
    let cursors = (0..257)
        .map(|index| ChannelResumeCursor::new(SessionChannel::Control, index, index))
        .collect();
    let error = SessionResumeRequest {
        cursors,
        ..request()
    }
    .validate()
    .expect_err("cursor list must be bounded")
    .downcast_inner::<ProtocolLimitError>()
    .expect("shared batch error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::BatchTooLarge {
            field: "cursors",
            count: 257,
            max: 256,
        }
    );
}

#[test]
fn request_rejects_zero_request_timestamp() {
    let error = SessionResumeRequest {
        requested_at_ms: 0,
        ..request()
    };

    assert_eq!(
        resume_error(error.validate()),
        ResumeError::ZeroTimestamp {
            field: "requested_at_ms"
        }
    );
}

#[test]
fn request_rejects_expiry_at_or_before_request_time() {
    for expires_at_ms in [100, 99] {
        let error = SessionResumeRequest {
            expires_at_ms,
            ..request()
        };
        assert_eq!(
            resume_error(error.validate()),
            ResumeError::ExpiryNotAfterRequest {
                requested_at_ms: 100,
                expires_at_ms,
            }
        );
    }
}

#[test]
fn request_reports_expiry_at_the_exact_boundary() {
    let request = request();

    assert!(!request.is_expired_at(199));
    assert!(request.is_expired_at(200));
    assert!(request.is_expired_at(201));
}

#[test]
fn request_rejects_empty_and_whitespace_session_identifiers() {
    let mut empty = request();
    empty.session_id.clear();
    assert!(empty.validate().is_err());

    let whitespace = SessionResumeRequest {
        session_id: "  ".to_owned(),
        ..request()
    };
    let error = whitespace
        .validate()
        .expect_err("whitespace session ID must be rejected")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared identifier error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier {
            field: "session_id"
        }
    );
}

#[test]
fn accepted_response_confirms_resume_and_keeps_fallback_temporarily_alive() {
    let accepted = SessionResumeAccepted::new(SESSION_ID, migration(), cursors(), 150, 300)
        .expect("accepted response should be valid");
    let value = serde_json::to_value(&accepted).expect("accepted response should serialize");

    assert_eq!(value["resumed"], true);
    assert_eq!(value["fallback_expires_at_ms"], 300);
    assert!(value.get("resume_key").is_none());
    assert!(!accepted.fallback_is_expired_at(299));
    assert!(accepted.fallback_is_expired_at(300));
}

#[test]
fn accepted_response_cannot_claim_resumed_false() {
    let response = SessionResumeAccepted {
        resumed: false,
        ..SessionResumeAccepted::new(SESSION_ID, migration(), cursors(), 150, 300)
            .expect("fixture should be valid")
    };

    assert_eq!(
        resume_error(response.validate()),
        ResumeError::AcceptedWithoutResume
    );
}

#[test]
fn accepted_response_requires_fallback_expiry_after_resume_time() {
    for fallback_expires_at_ms in [150, 149] {
        let response = SessionResumeAccepted {
            fallback_expires_at_ms,
            ..SessionResumeAccepted::new(SESSION_ID, migration(), cursors(), 150, 300)
                .expect("fixture should be valid")
        };
        assert_eq!(
            resume_error(response.validate()),
            ResumeError::FallbackExpiryNotAfterResume
        );
    }
}

#[test]
fn accepted_response_has_no_resume_key_or_private_transport_error() {
    let accepted = SessionResumeAccepted::new(SESSION_ID, migration(), cursors(), 150, 300)
        .expect("accepted response should be valid");
    let encoded = serde_json::to_string(&accepted).expect("accepted response should serialize");

    assert!(!encoded.contains("resume_key"));
    assert!(!encoded.contains("private_key"));
    assert!(!encoded.contains("stderr"));
}

#[test]
fn rejected_response_contains_only_safe_reason_and_retryability() {
    let rejected =
        SessionResumeRejected::new(SESSION_ID, ResumeRejectionReason::ExpiredResumeKey, true)
            .expect("rejected response should be valid");
    let value = serde_json::to_value(&rejected).expect("rejected response should serialize");

    assert_eq!(value["reason"], "expired_resume_key");
    assert_eq!(value["retryable"], true);
    assert!(value.get("resume_key").is_none());
    assert!(value.get("old_channel_id").is_none());
}

#[test]
fn all_rejection_reasons_have_stable_wire_names() {
    let reasons = [
        (
            ResumeRejectionReason::InvalidResumeKey,
            "invalid_resume_key",
        ),
        (
            ResumeRejectionReason::ExpiredResumeKey,
            "expired_resume_key",
        ),
        (ResumeRejectionReason::SessionMismatch, "session_mismatch"),
        (
            ResumeRejectionReason::ChannelAlreadyActive,
            "channel_already_active",
        ),
        (ResumeRejectionReason::UnknownChannel, "unknown_channel"),
        (ResumeRejectionReason::SequenceConflict, "sequence_conflict"),
        (
            ResumeRejectionReason::TransportUnavailable,
            "transport_unavailable",
        ),
        (
            ResumeRejectionReason::ProtocolViolation,
            "protocol_violation",
        ),
        (ResumeRejectionReason::Unauthorized, "unauthorized"),
        (ResumeRejectionReason::PeerUnavailable, "peer_unavailable"),
    ];

    for (reason, wire_name) in reasons {
        assert_eq!(
            serde_json::to_string(&reason).expect("reason should serialize"),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn unknown_optional_resume_fields_are_ignored() {
    let mut value = serde_json::to_value(request()).expect("request should serialize");
    value["future_resume_field"] = json!({ "ignored": true });

    let decoded: SessionResumeRequest =
        serde_json::from_value(value).expect("unknown optional fields should be ignored");
    assert_eq!(decoded, request());
}

#[test]
fn resume_request_does_not_coerce_numbers_or_booleans_from_strings() {
    let mut timestamp = serde_json::to_value(request()).expect("request should serialize");
    timestamp["requested_at_ms"] = json!("100");
    assert!(serde_json::from_value::<SessionResumeRequest>(timestamp).is_err());

    let mut cursor = serde_json::to_value(request()).expect("request should serialize");
    cursor["cursors"][0]["last_sent_seq"] = json!(true);
    assert!(serde_json::from_value::<SessionResumeRequest>(cursor).is_err());
}

#[test]
fn resume_request_debug_does_not_leak_the_resume_key() {
    let debug = format!("{:?}", request());

    assert!(!debug.contains(RESUME_KEY_VALUE));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn response_session_ids_are_validated_too() {
    let rejected = SessionResumeRejected {
        session_id: "../../private".to_owned(),
        reason: ResumeRejectionReason::ProtocolViolation,
        retryable: false,
    };
    assert_eq!(
        resume_error(rejected.validate()),
        ResumeError::InvalidIdentifierCharacter {
            field: "session_id"
        }
    );

    let accepted = SessionResumeAccepted {
        session_id: "session\n01".to_owned(),
        ..SessionResumeAccepted::new(SESSION_ID, migration(), cursors(), 150, 300)
            .expect("fixture should be valid")
    };
    assert_eq!(
        resume_error(accepted.validate()),
        ResumeError::ControlCharacter {
            field: "session_id"
        }
    );
}
