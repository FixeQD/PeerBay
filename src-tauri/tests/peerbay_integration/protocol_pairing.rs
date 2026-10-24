use serde_json::json;

use peerbay_lib::protocol::{
    MessageEnvelope, MessageType, PairingAccepted, PairingCancellationReason, PairingCancelled,
    PairingCode, PairingCommit, PairingConfirm, PairingError, PairingMessageType, PairingNonce,
    PairingRejected, PairingRejectionReason, PairingReveal, PairingStart, ProtocolLimitError,
};

const PAIRING_ID: &str = "pairing-01";
const DEVICE_ID: &str = "device-linux-01";
const FINGERPRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const COMMITMENT: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const NONCE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SESSION_TOKEN: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SAS_CODE: &str = "042731";

fn pairing_start() -> PairingStart {
    PairingStart::new(PAIRING_ID, DEVICE_ID, FINGERPRINT, vec![1], COMMITMENT)
        .expect("pairing start fixture should be valid")
}

fn error(result: eros::Result<()>) -> PairingError {
    result
        .expect_err("pairing validation should fail")
        .downcast_inner::<PairingError>()
        .expect("pairing error should be preserved")
}

#[test]
fn pairing_message_identifiers_are_mapped_to_the_pairing_channel() {
    let identifiers = [
        (PairingMessageType::Start, "pair.start"),
        (PairingMessageType::Commit, "pair.commit"),
        (PairingMessageType::Nonce, "pair.nonce"),
        (PairingMessageType::Reveal, "pair.reveal"),
        (PairingMessageType::Code, "pair.code"),
        (PairingMessageType::Confirm, "pair.confirm"),
        (PairingMessageType::Accepted, "pair.accepted"),
        (PairingMessageType::Rejected, "pair.rejected"),
        (PairingMessageType::Cancelled, "pair.cancelled"),
    ];

    for (message_type, wire_name) in identifiers {
        let message = MessageType::Pairing(message_type);
        assert_eq!(message.as_str(), wire_name);
        assert_eq!(
            message.channel(),
            peerbay_lib::protocol::MessageChannel::Pairing
        );
        assert_eq!(
            serde_json::to_string(&message).expect("pairing identifier should serialize"),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn pairing_start_serializes_public_parameters_with_canonical_names() {
    let value = serde_json::to_value(pairing_start()).expect("pairing start should serialize");

    assert_eq!(value["pairing_id"], PAIRING_ID);
    assert_eq!(value["device_id"], DEVICE_ID);
    assert_eq!(value["certificate_fingerprint"], FINGERPRINT);
    assert_eq!(value["protocol_versions"], json!([1]));
    assert_eq!(value["nonce_commitment"], COMMITMENT);
    assert!(value.get("nonce").is_none());
    assert!(value.get("session_token").is_none());
}

#[test]
fn pairing_start_roundtrips_inside_the_versioned_envelope() {
    let envelope = MessageEnvelope::new(
        "pair-message-1",
        MessageType::Pairing(PairingMessageType::Start),
        "session-before-trust",
        1,
        1_800_000_000_000,
        pairing_start(),
    );

    let encoded = serde_json::to_string(&envelope).expect("pair.start should serialize");
    let decoded: MessageEnvelope<PairingStart> =
        serde_json::from_str(&encoded).expect("pair.start should deserialize");

    assert_eq!(decoded, envelope);
    assert_eq!(decoded.message_type.as_str(), "pair.start");
}

#[test]
fn all_pairing_stage_messages_validate_with_the_same_pairing_id() {
    let messages = [
        serde_json::to_value(pairing_start()).expect("start should encode"),
        serde_json::to_value(
            PairingCommit::new(PAIRING_ID, COMMITMENT).expect("commit should be valid"),
        )
        .expect("commit should encode"),
        serde_json::to_value(PairingNonce::new(PAIRING_ID, NONCE).expect("nonce should be valid"))
            .expect("nonce should encode"),
        serde_json::to_value(
            PairingReveal::new(PAIRING_ID, NONCE).expect("reveal should be valid"),
        )
        .expect("reveal should encode"),
        serde_json::to_value(
            PairingCode::new(PAIRING_ID, SAS_CODE, 100).expect("code should be valid"),
        )
        .expect("code should encode"),
        serde_json::to_value(
            PairingConfirm::accepted(PAIRING_ID, SAS_CODE).expect("confirm should be valid"),
        )
        .expect("confirm should encode"),
        serde_json::to_value(
            PairingAccepted::new(PAIRING_ID, SESSION_TOKEN, 100).expect("accepted should be valid"),
        )
        .expect("accepted should encode"),
        serde_json::to_value(
            PairingRejected::new(PAIRING_ID, PairingRejectionReason::UserDenied, false)
                .expect("rejected should be valid"),
        )
        .expect("rejected should encode"),
        serde_json::to_value(
            PairingCancelled::new(PAIRING_ID, PairingCancellationReason::UserRequested)
                .expect("cancelled should be valid"),
        )
        .expect("cancelled should encode"),
    ];

    for message in messages {
        assert_eq!(message["pairing_id"], PAIRING_ID);
    }
}

#[test]
fn pairing_start_requires_at_least_one_protocol_version() {
    let mut message = pairing_start();
    message.protocol_versions.clear();

    assert_eq!(
        error(message.validate()),
        PairingError::EmptyProtocolVersions
    );
}

#[test]
fn pairing_start_rejects_protocol_version_zero() {
    let mut message = pairing_start();
    message.protocol_versions = vec![0];

    assert_eq!(
        error(message.validate()),
        PairingError::InvalidProtocolVersion { version: 0 }
    );
}

#[test]
fn pairing_start_rejects_duplicate_protocol_versions() {
    let mut message = pairing_start();
    message.protocol_versions = vec![1, 2, 1];

    assert_eq!(
        error(message.validate()),
        PairingError::DuplicateProtocolVersion { version: 1 }
    );
}

#[test]
fn pairing_start_rejects_a_protocol_version_batch_over_the_shared_limit() {
    let mut message = pairing_start();
    message.protocol_versions = (1..=257).collect();

    let error = message
        .validate()
        .expect_err("pairing protocol versions must be bounded")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared batch limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::BatchTooLarge {
            field: "protocol_versions",
            count: 257,
            max: 256,
        }
    );
}

#[test]
fn pairing_identifiers_reject_empty_and_whitespace_values() {
    let mut empty = pairing_start();
    empty.pairing_id.clear();
    assert!(empty.validate().is_err());

    let mut whitespace = pairing_start();
    whitespace.device_id = "   ".to_owned();
    let error = whitespace
        .validate()
        .expect_err("whitespace-only device IDs must be rejected")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared identifier error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier { field: "device_id" }
    );
}

#[test]
fn pairing_identifiers_reject_paths_control_characters_and_unicode() {
    let mut path = pairing_start();
    path.pairing_id = "../../pairing".to_owned();
    assert_eq!(
        error(path.validate()),
        PairingError::InvalidIdentifierCharacter {
            field: "pairing_id"
        }
    );

    let mut control = pairing_start();
    control.device_id = "device\n01".to_owned();
    assert_eq!(
        error(control.validate()),
        PairingError::ControlCharacter { field: "device_id" }
    );

    let mut unicode = pairing_start();
    unicode.device_id = "telefon📱".to_owned();
    assert_eq!(
        error(unicode.validate()),
        PairingError::InvalidIdentifierCharacter { field: "device_id" }
    );
}

#[test]
fn fingerprints_commitments_nonces_and_tokens_require_256_bit_lowercase_hex() {
    let mut fingerprint = pairing_start();
    fingerprint.certificate_fingerprint = "00".to_owned();
    assert_eq!(
        error(fingerprint.validate()),
        PairingError::InvalidHexLength {
            field: "certificate_fingerprint",
            length: 2,
            expected: 64,
        }
    );

    let mut commitment = pairing_start();
    commitment.nonce_commitment = "g".repeat(64);
    assert_eq!(
        error(commitment.validate()),
        PairingError::InvalidHexValue {
            field: "nonce_commitment"
        }
    );

    let mut nonce = PairingNonce::new(PAIRING_ID, NONCE).expect("nonce should be valid");
    nonce.nonce = "A".repeat(64);
    assert_eq!(
        error(nonce.validate()),
        PairingError::InvalidHexValue { field: "nonce" }
    );

    let mut token = PairingAccepted::new(PAIRING_ID, SESSION_TOKEN, 1).expect("token valid");
    token.session_token = "f".repeat(63);
    assert_eq!(
        error(token.validate()),
        PairingError::InvalidHexLength {
            field: "session_token",
            length: 63,
            expected: 64,
        }
    );
}

#[test]
fn commit_nonce_and_reveal_are_bound_to_a_valid_pairing_id() {
    let commit = PairingCommit::new(PAIRING_ID, COMMITMENT).expect("commit should be valid");
    let nonce = PairingNonce::new(PAIRING_ID, NONCE).expect("nonce should be valid");
    let reveal = PairingReveal::new(PAIRING_ID, NONCE).expect("reveal should be valid");

    assert_eq!(commit.pairing_id, PAIRING_ID);
    assert_eq!(nonce.pairing_id, PAIRING_ID);
    assert_eq!(reveal.pairing_id, PAIRING_ID);
}

#[test]
fn sas_codes_require_exactly_six_ascii_digits() {
    let too_short = PairingCode::new(PAIRING_ID, "12345", 1).expect_err("short SAS is invalid");
    assert_eq!(
        too_short
            .downcast_inner::<PairingError>()
            .expect("pairing error should be preserved"),
        PairingError::InvalidSasCodeLength {
            length: 5,
            expected: 6,
        }
    );

    let non_digit =
        PairingCode::new(PAIRING_ID, "12x456", 1).expect_err("non-digit SAS is invalid");
    assert_eq!(
        non_digit
            .downcast_inner::<PairingError>()
            .expect("pairing error should be preserved"),
        PairingError::InvalidSasCodeValue
    );

    PairingCode::new(PAIRING_ID, "000000", 1).expect("zero-prefixed six digit SAS is valid");
}

#[test]
fn sas_code_expiry_must_be_nonzero() {
    let error = PairingCode::new(PAIRING_ID, SAS_CODE, 0)
        .expect_err("zero expiry must be rejected")
        .downcast_inner::<PairingError>()
        .expect("pairing error should be preserved");

    assert_eq!(error, PairingError::ZeroExpiry);
}

#[test]
fn accepted_confirmation_requires_the_sas_code() {
    let accepted = PairingConfirm::accepted(PAIRING_ID, SAS_CODE)
        .expect("accepted confirmation should be valid");
    assert!(accepted.confirmed);
    assert_eq!(accepted.sas_code.as_deref(), Some(SAS_CODE));

    let missing = PairingConfirm {
        pairing_id: PAIRING_ID.to_owned(),
        sas_code: None,
        confirmed: true,
    };
    assert_eq!(error(missing.validate()), PairingError::MissingSasCode);
}

#[test]
fn denied_confirmation_carries_no_sas_code() {
    let denied = PairingConfirm::denied(PAIRING_ID).expect("denied confirmation should be valid");
    assert!(!denied.confirmed);
    assert!(denied.sas_code.is_none());

    let malformed = PairingConfirm {
        pairing_id: PAIRING_ID.to_owned(),
        sas_code: Some(SAS_CODE.to_owned()),
        confirmed: false,
    };
    assert_eq!(
        error(malformed.validate()),
        PairingError::SasCodeOnDeniedConfirmation
    );
}

#[test]
fn accepted_message_requires_a_nonzero_expiring_session_token() {
    let accepted = PairingAccepted::new(PAIRING_ID, SESSION_TOKEN, 1)
        .expect("accepted pairing should be valid");
    assert_eq!(accepted.session_token, SESSION_TOKEN);

    let zero_expiry = PairingAccepted {
        pairing_id: PAIRING_ID.to_owned(),
        session_token: SESSION_TOKEN.to_owned(),
        expires_at_ms: 0,
    };
    assert_eq!(error(zero_expiry.validate()), PairingError::ZeroExpiry);
}

#[test]
fn rejected_messages_use_safe_reason_codes_and_retryability() {
    let rejected = PairingRejected::new(PAIRING_ID, PairingRejectionReason::CodeMismatch, true)
        .expect("rejected pairing should be valid");
    let value = serde_json::to_value(&rejected).expect("rejection should serialize");

    assert_eq!(value["reason"], "code_mismatch");
    assert_eq!(value["retryable"], true);
    assert!(value.get("nonce").is_none());
    assert!(value.get("session_token").is_none());
}

#[test]
fn cancelled_messages_use_safe_reason_codes_without_temporary_secrets() {
    let cancelled = PairingCancelled::new(PAIRING_ID, PairingCancellationReason::PeerDisconnected)
        .expect("cancelled pairing should be valid");
    let value = serde_json::to_value(&cancelled).expect("cancellation should serialize");

    assert_eq!(value["reason"], "peer_disconnected");
    assert!(value.get("nonce").is_none());
    assert!(value.get("session_token").is_none());
    assert!(value.get("certificate_fingerprint").is_none());
}

#[test]
fn pairing_rejection_and_cancellation_reason_enums_have_stable_wire_names() {
    assert_eq!(
        serde_json::to_string(&PairingRejectionReason::FingerprintMismatch)
            .expect("reason should serialize"),
        "\"fingerprint_mismatch\""
    );
    assert_eq!(
        serde_json::to_string(&PairingCancellationReason::BackendShutdown)
            .expect("reason should serialize"),
        "\"backend_shutdown\""
    );
}

#[test]
fn unknown_optional_pairing_fields_are_ignored() {
    let mut value = serde_json::to_value(pairing_start()).expect("start should serialize");
    value["future_pairing_field"] = json!({ "not_a_secret": true });

    let decoded: PairingStart =
        serde_json::from_value(value).expect("unknown optional fields should be ignored");
    assert_eq!(decoded, pairing_start());
}

#[test]
fn pairing_start_does_not_contain_private_key_or_session_token_fields() {
    let value = serde_json::to_value(pairing_start()).expect("start should serialize");
    let object = value.as_object().expect("start should be an object");

    for forbidden in [
        "private_key",
        "privateKey",
        "session_token",
        "password",
        "secret",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "pair.start unexpectedly exposed field {forbidden}"
        );
    }
}

#[test]
fn pairing_stage_messages_preserve_leading_zero_sas_codes() {
    let code = PairingCode::new(PAIRING_ID, "000007", 10).expect("SAS should be valid");
    let encoded = serde_json::to_string(&code).expect("code should serialize");
    let decoded: PairingCode = serde_json::from_str(&encoded).expect("code should deserialize");

    assert_eq!(decoded.sas_code, "000007");
}

#[test]
fn pairing_confirmation_does_not_coerce_boolean_values_from_strings() {
    let value = json!({
        "pairing_id": PAIRING_ID,
        "sas_code": SAS_CODE,
        "confirmed": "true"
    });

    let result = serde_json::from_value::<PairingConfirm>(value);
    assert!(result.is_err(), "string booleans must not be accepted");
}

#[test]
fn pairing_start_does_not_coerce_protocol_versions_from_strings() {
    let mut value = serde_json::to_value(pairing_start()).expect("start should serialize");
    value["protocol_versions"] = json!(["1"]);

    let result = serde_json::from_value::<PairingStart>(value);
    assert!(
        result.is_err(),
        "string protocol versions must not be accepted"
    );
}
