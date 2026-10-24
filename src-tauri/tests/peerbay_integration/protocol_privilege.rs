use serde_json::json;

use peerbay_lib::protocol::{
    MessageChannel, MessageEnvelope, MessageType, PhoneMessageType, PrivilegeAdbTransport,
    PrivilegeAuthority, PrivilegeBackendSnapshot, PrivilegeCancelRequest,
    PrivilegeCancellationReason, PrivilegeCapabilities, PrivilegeDecision, PrivilegeError,
    PrivilegeProof, PrivilegeProvider, PrivilegeRequest, PrivilegeState, PrivilegeStateMessage,
    ProtocolLimitError, ProtocolLimits,
};

const SESSION_ID: &str = "session-phone-01";

fn proof() -> PrivilegeProof {
    PrivilegeProof::new(
        PrivilegeProvider::Accessibility,
        PrivilegeAuthority::UserGrantedService,
        "com.fixeq.peerbay",
        Some(10_042),
        Some("accessibility.service".to_owned()),
        Some("1.2.3".to_owned()),
        None,
        Some("u:r:accessibility:s0".to_owned()),
        100,
        200,
        Some(300),
        vec![
            "service_connected".to_owned(),
            "operation_probe_ok".to_owned(),
        ],
    )
    .expect("proof fixture should be valid")
}

fn adb_proof() -> PrivilegeProof {
    PrivilegeProof::new(
        PrivilegeProvider::WirelessAdb,
        PrivilegeAuthority::AdbShell,
        "com.fixeq.peerbay",
        Some(20_000),
        None,
        Some("35.0.2".to_owned()),
        Some(PrivilegeAdbTransport::Wireless),
        Some("u:r:shell:s0".to_owned()),
        100,
        200,
        Some(300),
        vec!["shell_uid_confirmed".to_owned()],
    )
    .expect("ADB proof fixture should be valid")
}

fn ready_state() -> PrivilegeStateMessage {
    PrivilegeStateMessage::new(
        "request-1",
        "phone.input.inject",
        PrivilegeState::Ready,
        PrivilegeDecision::Allowed,
        "ready",
        Some(PrivilegeProvider::Accessibility),
        Some(PrivilegeAuthority::UserGrantedService),
        Vec::new(),
        false,
        None,
        Some(proof()),
        200,
        Some(300),
    )
    .expect("ready privilege state should be valid")
}

fn backend() -> PrivilegeBackendSnapshot {
    PrivilegeBackendSnapshot::new(
        PrivilegeProvider::WirelessAdb,
        PrivilegeState::Ready,
        Some(PrivilegeAuthority::AdbShell),
        vec!["phone.screen.read".to_owned(), "phone.input.adb".to_owned()],
        Vec::new(),
        false,
        None,
        Some(adb_proof()),
        200,
        Some(300),
    )
    .expect("backend fixture should be valid")
}

fn privilege_error(result: eros::Result<()>) -> PrivilegeError {
    result
        .expect_err("privilege validation should fail")
        .downcast_inner::<PrivilegeError>()
        .expect("privilege error should be preserved")
}

#[test]
fn phone_privilege_message_identifiers_use_the_phone_channel() {
    let identifiers = [
        (
            MessageType::Phone(PhoneMessageType::PrivilegeState),
            "phone.privilege.state",
        ),
        (
            MessageType::Phone(PhoneMessageType::PrivilegeRequest),
            "phone.privilege.request",
        ),
        (
            MessageType::Phone(PhoneMessageType::PrivilegeCancel),
            "phone.privilege.cancel",
        ),
        (
            MessageType::Phone(PhoneMessageType::PrivilegeCapabilities),
            "phone.privilege.capabilities",
        ),
    ];

    for (message, wire_name) in identifiers {
        assert_eq!(message.channel(), MessageChannel::Phone);
        assert_eq!(message.as_str(), wire_name);
        assert_eq!(
            serde_json::to_string(&message).unwrap(),
            format!("\"{wire_name}\"")
        );

        let decoded: MessageType = serde_json::from_str(&format!("\"{wire_name}\""))
            .expect("phone privilege identifier should deserialize");
        assert_eq!(decoded, message);
    }
}

#[test]
fn privilege_enums_have_stable_snake_case_wire_values() {
    let providers = [
        (PrivilegeProvider::StandardApp, "standard_app"),
        (PrivilegeProvider::RuntimePermission, "runtime_permission"),
        (PrivilegeProvider::SpecialAppAccess, "special_app_access"),
        (PrivilegeProvider::Accessibility, "accessibility"),
        (PrivilegeProvider::MediaProjection, "media_projection"),
        (PrivilegeProvider::CompanionDevice, "companion_device"),
        (PrivilegeProvider::UsbAdb, "usb_adb"),
        (PrivilegeProvider::WirelessAdb, "wireless_adb"),
        (PrivilegeProvider::Shizuku, "shizuku"),
        (PrivilegeProvider::Sui, "sui"),
        (PrivilegeProvider::Root, "root"),
        (PrivilegeProvider::DeviceOwner, "device_owner"),
    ];

    for (provider, wire_name) in providers {
        assert_eq!(
            serde_json::to_string(&provider).unwrap(),
            format!("\"{wire_name}\"")
        );
    }

    assert_eq!(
        serde_json::to_string(&PrivilegeAuthority::ShizukuShell).unwrap(),
        "\"shizuku_shell\""
    );
    assert_eq!(
        serde_json::to_string(&PrivilegeState::NeedsUserAction).unwrap(),
        "\"needs_user_action\""
    );
    assert_eq!(
        serde_json::to_string(&PrivilegeDecision::Degraded).unwrap(),
        "\"degraded\""
    );
    assert_eq!(
        serde_json::to_string(&PrivilegeCancellationReason::PeerDisconnected).unwrap(),
        "\"peer_disconnected\""
    );
}

#[test]
fn privilege_request_roundtrips_inside_the_versioned_envelope() {
    let request = PrivilegeRequest::new(
        "request-1",
        "phone.screen.read",
        Some(PrivilegeProvider::MediaProjection),
        100,
    )
    .expect("request should be valid");
    let envelope = MessageEnvelope::new(
        "privilege-message-1",
        MessageType::Phone(PhoneMessageType::PrivilegeRequest),
        SESSION_ID,
        1,
        100,
        request.clone(),
    );

    let encoded = serde_json::to_string(&envelope).expect("request envelope should serialize");
    let decoded: MessageEnvelope<PrivilegeRequest> =
        serde_json::from_str(&encoded).expect("request envelope should deserialize");

    assert_eq!(decoded, envelope);
    assert_eq!(decoded.message_type.channel(), MessageChannel::Phone);
}

#[test]
fn privilege_request_serializes_only_typed_non_secret_fields() {
    let request = PrivilegeRequest::new(
        "request-1",
        "phone.apps.enumerate",
        Some(PrivilegeProvider::Shizuku),
        100,
    )
    .expect("request should be valid");
    let value = serde_json::to_value(request).expect("request should serialize");

    assert_eq!(value["request_id"], "request-1");
    assert_eq!(value["capability"], "phone.apps.enumerate");
    assert_eq!(value["provider_hint"], "shizuku");
    assert_eq!(value["requested_at_ms"], 100);
    assert!(!value.to_string().contains("token"));
    assert!(!value.to_string().contains("private"));
}

#[test]
fn privilege_request_rejects_empty_identifiers_and_zero_timestamp() {
    let error = PrivilegeRequest::new("", "phone.screen.read", None, 100)
        .expect_err("empty request IDs must be rejected")
        .downcast_inner::<ProtocolLimitError>()
        .expect("empty request ID should preserve the shared limit error");
    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier {
            field: "request_id"
        }
    );
    assert_eq!(
        privilege_error(PrivilegeRequest::new("request-1", "phone/screen", None, 100).map(|_| ())),
        PrivilegeError::InvalidIdentifierCharacter {
            field: "capability"
        }
    );
    assert_eq!(
        privilege_error(
            PrivilegeRequest::new("request-1", "phone.screen.read", None, 0).map(|_| ())
        ),
        PrivilegeError::ZeroTimestamp {
            field: "requested_at_ms"
        }
    );
}

#[test]
fn privilege_request_does_not_coerce_json_types() {
    let value = json!({
        "request_id": "request-1",
        "capability": "phone.screen.read",
        "provider_hint": "media_projection",
        "requested_at_ms": "100"
    });

    assert!(serde_json::from_value::<PrivilegeRequest>(value).is_err());
}

#[test]
fn privilege_cancel_has_a_safe_reason_and_no_provider_secret() {
    let cancel =
        PrivilegeCancelRequest::new("request-1", PrivilegeCancellationReason::UserRequested)
            .expect("cancel should be valid");
    let value = serde_json::to_value(cancel).expect("cancel should serialize");

    assert_eq!(value["request_id"], "request-1");
    assert_eq!(value["reason"], "user_requested");
    assert!(value.get("resume_key").is_none());
    assert!(value.get("token").is_none());
}

#[test]
fn privilege_proof_roundtrips_safe_probe_metadata() {
    let original = proof();
    let encoded = serde_json::to_string(&original).expect("proof should serialize");
    let decoded: PrivilegeProof = serde_json::from_str(&encoded).expect("proof should deserialize");

    assert_eq!(decoded, original);
    assert!(encoded.contains("operation_probe_ok"));
    assert!(!encoded.contains("shell output"));
    assert!(!encoded.contains("private/path"));
}

#[test]
fn privilege_proof_rejects_inverted_timestamps_and_mismatched_adb_metadata() {
    let error = privilege_error(
        PrivilegeProof::new(
            PrivilegeProvider::Accessibility,
            PrivilegeAuthority::UserGrantedService,
            "com.fixeq.peerbay",
            None,
            None,
            None,
            None,
            None,
            200,
            100,
            None,
            Vec::new(),
        )
        .map(|_| ()),
    );
    assert_eq!(
        error,
        PrivilegeError::TimestampOrder {
            earlier_field: "started_at_ms",
            later_field: "checked_at_ms",
        }
    );

    let error = privilege_error(
        PrivilegeProof::new(
            PrivilegeProvider::Accessibility,
            PrivilegeAuthority::UserGrantedService,
            "com.fixeq.peerbay",
            None,
            None,
            None,
            Some(PrivilegeAdbTransport::Usb),
            None,
            100,
            100,
            None,
            Vec::new(),
        )
        .map(|_| ()),
    );
    assert_eq!(error, PrivilegeError::AdbTransportRequiresAdbProvider);
}

#[test]
fn privilege_state_reports_local_action_without_leaking_a_secret() {
    let state = PrivilegeStateMessage::new(
        "request-2",
        "phone.screen.read",
        PrivilegeState::NeedsUserAction,
        PrivilegeDecision::NeedsUserAction,
        "open_media_projection_consent",
        Some(PrivilegeProvider::MediaProjection),
        Some(PrivilegeAuthority::UserGrantedService),
        Vec::new(),
        true,
        Some("open_media_projection_consent".to_owned()),
        None,
        200,
        Some(300),
    )
    .expect("needs-user-action state should be valid");
    let value = serde_json::to_value(state).expect("state should serialize");

    assert_eq!(value["decision"], "needs_user_action");
    assert_eq!(value["next_action"], "open_media_projection_consent");
    assert!(value.get("resume_key").is_none());
    assert!(value.get("private_key").is_none());
}

#[test]
fn privilege_state_rejects_inconsistent_action_fields() {
    let error = privilege_error(
        PrivilegeStateMessage::new(
            "request-1",
            "phone.screen.read",
            PrivilegeState::NeedsUserAction,
            PrivilegeDecision::NeedsUserAction,
            "needs_user_action",
            None,
            None,
            Vec::new(),
            false,
            Some("open_media_projection_consent".to_owned()),
            None,
            100,
            None,
        )
        .map(|_| ()),
    );
    assert_eq!(error, PrivilegeError::UnexpectedNextAction);

    let error = privilege_error(
        PrivilegeStateMessage::new(
            "request-1",
            "phone.screen.read",
            PrivilegeState::NeedsUserAction,
            PrivilegeDecision::NeedsUserAction,
            "needs_user_action",
            None,
            None,
            Vec::new(),
            false,
            None,
            None,
            100,
            None,
        )
        .map(|_| ()),
    );
    assert_eq!(error, PrivilegeError::DecisionRequiresUserAction);

    let error = privilege_error(
        PrivilegeStateMessage::new(
            "request-1",
            "phone.screen.read",
            PrivilegeState::Ready,
            PrivilegeDecision::Allowed,
            "ready",
            None,
            None,
            Vec::new(),
            true,
            None,
            None,
            100,
            None,
        )
        .map(|_| ()),
    );
    assert_eq!(error, PrivilegeError::MissingNextAction);
}

#[test]
fn privilege_state_rejects_expiry_at_the_check_boundary() {
    let error = privilege_error(
        PrivilegeStateMessage::new(
            "request-1",
            "phone.screen.read",
            PrivilegeState::Ready,
            PrivilegeDecision::Allowed,
            "expired",
            None,
            None,
            Vec::new(),
            false,
            None,
            None,
            100,
            Some(100),
        )
        .map(|_| ()),
    );
    assert_eq!(
        error,
        PrivilegeError::ExpiryNotAfterCheck {
            field: "expires_at_ms",
            checked_at_ms: 100,
            expires_at_ms: 100,
        }
    );
}

#[test]
fn privilege_state_rejects_proof_that_does_not_match_reported_provider() {
    let error = privilege_error(
        PrivilegeStateMessage::new(
            "request-1",
            "phone.input.inject",
            PrivilegeState::Ready,
            PrivilegeDecision::Allowed,
            "ready",
            Some(PrivilegeProvider::Root),
            Some(PrivilegeAuthority::RootShell),
            Vec::new(),
            false,
            None,
            Some(proof()),
            200,
            Some(300),
        )
        .map(|_| ()),
    );
    assert_eq!(error, PrivilegeError::ProofProviderMismatch);
}

#[test]
fn privilege_capabilities_match_the_documented_android_wire_shape() {
    let capabilities =
        PrivilegeCapabilities::new(vec![backend()]).expect("capability snapshot should be valid");
    let value = serde_json::to_value(capabilities).expect("capabilities should serialize");

    assert_eq!(value["backends"][0]["id"], "wireless_adb");
    assert_eq!(value["backends"][0]["state"], "ready");
    assert_eq!(value["backends"][0]["authority"], "adb_shell");
    assert_eq!(
        value["backends"][0]["features"],
        json!(["phone.screen.read", "phone.input.adb"])
    );
    assert!(value.to_string().find("root-token").is_none());
    assert!(value.to_string().find("private/path").is_none());
}

#[test]
fn privilege_capabilities_roundtrip_and_ignore_future_optional_fields() {
    let mut value = serde_json::to_value(PrivilegeCapabilities::new(vec![backend()]).unwrap())
        .expect("capabilities should serialize");
    value["future_capability_field"] = json!({ "opaque": true });
    value["backends"][0]["future_backend_field"] = json!("ignored");

    let decoded: PrivilegeCapabilities =
        serde_json::from_value(value).expect("unknown optional fields should be ignored");
    assert_eq!(decoded.backends.len(), 1);
    assert_eq!(decoded.backends[0].id, PrivilegeProvider::WirelessAdb);
}

#[test]
fn privilege_capabilities_reject_duplicate_backends_and_features() {
    let duplicate_backends = PrivilegeCapabilities::new(vec![backend(), backend()])
        .expect_err("duplicate providers must be rejected")
        .downcast_inner::<PrivilegeError>()
        .expect("duplicate backend error should be preserved");
    assert_eq!(
        duplicate_backends,
        PrivilegeError::DuplicateBackend {
            provider: PrivilegeProvider::WirelessAdb,
        }
    );

    let duplicate_features = PrivilegeBackendSnapshot::new(
        PrivilegeProvider::Accessibility,
        PrivilegeState::Ready,
        Some(PrivilegeAuthority::UserGrantedService),
        vec![
            "phone.input.inject".to_owned(),
            "phone.input.inject".to_owned(),
        ],
        Vec::new(),
        false,
        None,
        None,
        100,
        None,
    )
    .expect_err("duplicate feature IDs must be rejected")
    .downcast_inner::<PrivilegeError>()
    .expect("duplicate value error should be preserved");
    assert_eq!(
        duplicate_features,
        PrivilegeError::DuplicateValue {
            field: "features",
            value: "phone.input.inject".to_owned(),
        }
    );
}

#[test]
fn privilege_capabilities_reject_an_oversized_backend_batch() {
    let backends = vec![backend(); ProtocolLimits::default().max_batch_items() + 1];
    let error = PrivilegeCapabilities::new(backends)
        .expect_err("backend snapshot must obey the shared batch limit")
        .downcast_inner::<ProtocolLimitError>()
        .expect("batch limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::BatchTooLarge {
            field: "backends",
            count: ProtocolLimits::default().max_batch_items() + 1,
            max: ProtocolLimits::default().max_batch_items(),
        }
    );
}

#[test]
fn privilege_state_accepts_degraded_capability_with_explicit_limitation() {
    let state = PrivilegeStateMessage::new(
        "request-3",
        "phone.input.inject",
        PrivilegeState::Degraded,
        PrivilegeDecision::Degraded,
        "limited_by_provider",
        Some(PrivilegeProvider::Accessibility),
        Some(PrivilegeAuthority::UserGrantedService),
        vec![
            "no_secure_settings".to_owned(),
            "no_private_app_data".to_owned(),
        ],
        false,
        None,
        Some(proof()),
        200,
        Some(300),
    )
    .expect("degraded capability should be valid");

    assert_eq!(state.state, PrivilegeState::Degraded);
    assert_eq!(state.decision, PrivilegeDecision::Degraded);
    assert_eq!(state.limitations.len(), 2);
}

#[test]
fn privilege_state_message_roundtrips_with_the_phone_wire_identifier() {
    let original = ready_state();
    let envelope = MessageEnvelope::new(
        "privilege-state-1",
        MessageType::Phone(PhoneMessageType::PrivilegeState),
        SESSION_ID,
        7,
        200,
        original.clone(),
    );
    let encoded = serde_json::to_string(&envelope).expect("state envelope should serialize");
    let decoded: MessageEnvelope<PrivilegeStateMessage> =
        serde_json::from_str(&encoded).expect("state envelope should deserialize");

    assert_eq!(decoded.message_type.as_str(), "phone.privilege.state");
    assert_eq!(decoded.body, original);
}
