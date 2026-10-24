use serde_json::json;

use peerbay_lib::protocol::{
    ControlMessageType, FeaturePolicy, MessageEnvelope, MessageType, PolicyError, PolicyGetRequest,
    PolicyGetResponse, PolicyRejection, PolicyRejectionReason, PolicySetRequest, PolicySetResponse,
    ProtocolLimitError, ProtocolLimits, UserPolicyState,
};

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn allow(feature: &str) -> FeaturePolicy {
    FeaturePolicy::new(feature, UserPolicyState::Allow, Vec::new(), None, None)
        .expect("allow policy fixture should be valid")
}

fn deny(feature: &str) -> FeaturePolicy {
    FeaturePolicy::new(feature, UserPolicyState::Deny, Vec::new(), None, None)
        .expect("deny policy fixture should be valid")
}

fn limited(feature: &str) -> FeaturePolicy {
    FeaturePolicy::new(
        feature,
        UserPolicyState::AllowLimited,
        strings(&["no_private_payloads"]),
        Some(4096),
        Some(1_800_000_000_000),
    )
    .expect("limited policy fixture should be valid")
}

fn policy_error(result: eros::Result<()>) -> PolicyError {
    result
        .expect_err("policy validation should fail")
        .downcast_inner::<PolicyError>()
        .expect("policy error should be preserved")
}

#[test]
fn policy_states_use_stable_snake_case_wire_values() {
    let states = [
        (UserPolicyState::Unset, "unset"),
        (UserPolicyState::Allow, "allow"),
        (UserPolicyState::Deny, "deny"),
        (UserPolicyState::Ask, "ask"),
        (UserPolicyState::AllowLimited, "allow_limited"),
    ];

    for (state, wire_value) in states {
        assert_eq!(
            serde_json::to_string(&state).expect("policy state should serialize"),
            format!("\"{wire_value}\"")
        );
        let decoded: UserPolicyState = serde_json::from_str(&format!("\"{wire_value}\""))
            .expect("policy state should deserialize");
        assert_eq!(decoded, state);
    }
}

#[test]
fn rejection_reasons_use_stable_snake_case_wire_values() {
    let reasons = [
        (PolicyRejectionReason::UnknownFeature, "unknown_feature"),
        (PolicyRejectionReason::InvalidChange, "invalid_change"),
        (PolicyRejectionReason::RevisionConflict, "revision_conflict"),
        (PolicyRejectionReason::Unauthorized, "unauthorized"),
        (
            PolicyRejectionReason::CapabilityUnavailable,
            "capability_unavailable",
        ),
    ];

    for (reason, wire_value) in reasons {
        assert_eq!(
            serde_json::to_string(&reason).expect("rejection reason should serialize"),
            format!("\"{wire_value}\"")
        );
    }
}

#[test]
fn unrestricted_policy_serializes_all_wire_fields() {
    let policy = allow("clipboard.text");
    let value = serde_json::to_value(&policy).expect("feature policy should serialize");

    assert_eq!(value["feature"], "clipboard.text");
    assert_eq!(value["state"], "allow");
    assert_eq!(value["limitations"], json!([]));
    assert_eq!(value["max_bytes"], serde_json::Value::Null);
    assert_eq!(value["expires_at_ms"], serde_json::Value::Null);
}

#[test]
fn limited_policy_serializes_restrictions_without_private_data() {
    let policy = limited("files.send");
    let value = serde_json::to_value(&policy).expect("limited policy should serialize");

    assert_eq!(value["state"], "allow_limited");
    assert_eq!(value["limitations"], json!(["no_private_payloads"]));
    assert_eq!(value["max_bytes"], 4096);
    assert_eq!(value["expires_at_ms"], 1_800_000_000_000_u64);
    assert!(
        serde_json::to_string(&value)
            .expect("policy JSON should serialize")
            .find("private/path")
            .is_none()
    );
}

#[test]
fn policy_entries_roundtrip_all_states_and_optional_restrictions() {
    let original = vec![
        allow("clipboard.text"),
        deny("files.receive"),
        FeaturePolicy::new(
            "notifications.receive",
            UserPolicyState::Ask,
            Vec::new(),
            None,
            Some(7),
        )
        .expect("ask policy should be valid"),
        FeaturePolicy::new(
            "phone.screen.read",
            UserPolicyState::Unset,
            Vec::new(),
            None,
            None,
        )
        .expect("unset policy should be valid"),
        limited("files.send"),
    ];

    let encoded = serde_json::to_string(&original).expect("policies should serialize");
    let decoded: Vec<FeaturePolicy> =
        serde_json::from_str(&encoded).expect("policies should deserialize");

    assert_eq!(decoded, original);
}

#[test]
fn unknown_optional_policy_fields_are_ignored_during_decode() {
    let mut value = serde_json::to_value(allow("clipboard.text")).expect("policy should serialize");
    value["future_policy_field"] = json!({ "opaque": true });

    let decoded: FeaturePolicy =
        serde_json::from_value(value).expect("unknown optional field should be ignored");

    assert_eq!(decoded, allow("clipboard.text"));
}

#[test]
fn policy_get_request_roundtrips_inside_the_versioned_envelope() {
    let original = MessageEnvelope::new(
        "policy-get-1",
        MessageType::Control(ControlMessageType::PolicyGet),
        "session-1",
        10,
        1_800_000_000_000,
        PolicyGetRequest::for_features(strings(&["clipboard.text"]))
            .expect("policy filter should be valid"),
    );

    let encoded = serde_json::to_string(&original).expect("policy.get should serialize");
    let decoded: MessageEnvelope<PolicyGetRequest> =
        serde_json::from_str(&encoded).expect("policy.get should deserialize");

    assert_eq!(decoded, original);
    assert_eq!(decoded.message_type.as_str(), "policy.get");
}

#[test]
fn policy_set_response_roundtrips_inside_the_versioned_envelope() {
    let response = PolicySetResponse::new(8, vec![limited("files.send")], Vec::new())
        .expect("policy.set response should be valid");
    let original = MessageEnvelope::new(
        "policy-set-1",
        MessageType::Control(ControlMessageType::PolicySet),
        "session-1",
        11,
        1_800_000_000_001,
        response,
    );

    let value = serde_json::to_value(&original).expect("policy.set should serialize");

    assert_eq!(value["t"], "policy.set");
    assert_eq!(value["body"]["revision"], 8);
    assert_eq!(value["body"]["applied"][0]["state"], "allow_limited");
    assert_eq!(value["body"]["applied"][0]["max_bytes"], 4096);
}

#[test]
fn allow_limited_requires_a_limitation_or_byte_limit() {
    let error = FeaturePolicy::new(
        "files.send",
        UserPolicyState::AllowLimited,
        Vec::new(),
        None,
        None,
    )
    .expect_err("allow_limited without a restriction is meaningless")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::LimitedStateRequiresRestriction {
            feature: "files.send".to_owned(),
        }
    );
}

#[test]
fn a_byte_limit_alone_is_a_valid_limited_policy() {
    let policy = FeaturePolicy::new(
        "clipboard.text",
        UserPolicyState::AllowLimited,
        Vec::new(),
        Some(1024),
        None,
    )
    .expect("max_bytes is itself a restriction");

    assert_eq!(policy.max_bytes, Some(1024));
}

#[test]
fn limitations_cannot_be_attached_to_an_unrestricted_allow() {
    let error = FeaturePolicy::new(
        "files.send",
        UserPolicyState::Allow,
        strings(&["max_single_file"]),
        None,
        None,
    )
    .expect_err("a restricted policy must say allow_limited")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::RestrictionsRequireLimitedState {
            feature: "files.send".to_owned(),
        }
    );
}

#[test]
fn max_bytes_cannot_be_attached_to_deny() {
    let error = FeaturePolicy::new(
        "files.receive",
        UserPolicyState::Deny,
        Vec::new(),
        Some(1),
        None,
    )
    .expect_err("deny must not advertise an active byte allowance")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::RestrictionsRequireLimitedState {
            feature: "files.receive".to_owned(),
        }
    );
}

#[test]
fn expiry_is_not_allowed_for_unset_policy() {
    let error = FeaturePolicy::new(
        "clipboard.text",
        UserPolicyState::Unset,
        Vec::new(),
        None,
        Some(10),
    )
    .expect_err("unset has no active decision to expire")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::ExpiryNotAllowedForUnset {
            feature: "clipboard.text".to_owned(),
        }
    );
}

#[test]
fn zero_byte_limit_is_rejected() {
    let error = FeaturePolicy::new(
        "files.send",
        UserPolicyState::AllowLimited,
        strings(&["bounded"]),
        Some(0),
        None,
    )
    .expect_err("zero bytes is not a useful restriction")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::ZeroMaxBytes {
            feature: "files.send".to_owned(),
        }
    );
}

#[test]
fn zero_expiry_is_rejected() {
    let error = FeaturePolicy::new(
        "clipboard.text",
        UserPolicyState::Allow,
        Vec::new(),
        None,
        Some(0),
    )
    .expect_err("zero is not a valid expiry timestamp")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::ZeroExpiry {
            feature: "clipboard.text".to_owned(),
        }
    );
}

#[test]
fn duplicate_limitations_are_rejected() {
    let error = FeaturePolicy::new(
        "files.send",
        UserPolicyState::AllowLimited,
        strings(&["max_single_file", "max_single_file"]),
        None,
        None,
    )
    .expect_err("duplicate restrictions create ambiguous policy")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::DuplicateIdentifier {
            field: "limitations",
            value: "max_single_file".to_owned(),
        }
    );
}

#[test]
fn empty_feature_identifier_uses_the_shared_protocol_limit_error() {
    let error = FeaturePolicy::new("", UserPolicyState::Allow, Vec::new(), None, None)
        .expect_err("empty feature identifiers must be rejected")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared protocol limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier { field: "feature" }
    );
}

#[test]
fn whitespace_only_feature_identifier_is_rejected() {
    let error = FeaturePolicy::new("  ", UserPolicyState::Allow, Vec::new(), None, None)
        .expect_err("whitespace-only feature identifiers must be rejected")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared protocol limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier { field: "feature" }
    );
}

#[test]
fn surrounding_whitespace_in_feature_identifier_is_rejected() {
    let error = policy_error(
        FeaturePolicy {
            feature: " files.send".to_owned(),
            state: UserPolicyState::Allow,
            limitations: Vec::new(),
            max_bytes: None,
            expires_at_ms: None,
        }
        .validate(),
    );

    assert_eq!(
        error,
        PolicyError::UnexpectedWhitespace {
            field: "feature",
            index: None,
        }
    );
}

#[test]
fn path_separators_are_not_valid_policy_identifiers() {
    let error = policy_error(
        FeaturePolicy {
            feature: "../../private".to_owned(),
            state: UserPolicyState::Allow,
            limitations: Vec::new(),
            max_bytes: None,
            expires_at_ms: None,
        }
        .validate(),
    );

    assert_eq!(
        error,
        PolicyError::InvalidIdentifierCharacter {
            field: "feature",
            index: None,
            character: '/',
        }
    );
}

#[test]
fn control_characters_are_not_valid_policy_identifiers() {
    let error = policy_error(
        FeaturePolicy {
            feature: "files\n.send".to_owned(),
            state: UserPolicyState::Allow,
            limitations: Vec::new(),
            max_bytes: None,
            expires_at_ms: None,
        }
        .validate(),
    );

    assert_eq!(
        error,
        PolicyError::ControlCharacter {
            field: "feature",
            index: None,
        }
    );
}

#[test]
fn unicode_feature_identifiers_are_rejected_as_non_wire_identifiers() {
    let error = policy_error(
        FeaturePolicy {
            feature: "files.📦".to_owned(),
            state: UserPolicyState::Allow,
            limitations: Vec::new(),
            max_bytes: None,
            expires_at_ms: None,
        }
        .validate(),
    );

    assert_eq!(
        error,
        PolicyError::InvalidIdentifierCharacter {
            field: "feature",
            index: None,
            character: '📦',
        }
    );
}

#[test]
fn custom_limits_apply_to_policy_identifiers_and_lists() {
    let policy = FeaturePolicy {
        feature: "files.send".to_owned(),
        state: UserPolicyState::AllowLimited,
        limitations: strings(&["bounded"]),
        max_bytes: Some(1),
        expires_at_ms: None,
    };
    let limits = ProtocolLimits::new(1024, 1024, 4, 4, 1024);

    let error = policy
        .validate_with_limits(limits)
        .expect_err("custom string limits must be enforced")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::StringTooLong {
            field: "feature",
            length: 10,
            max: 4,
        }
    );
}

#[test]
fn policy_get_all_uses_an_empty_filter() {
    let request = PolicyGetRequest::all();

    assert!(request.features.is_empty());
    request.validate().expect("empty filter means all policies");
    assert_eq!(
        serde_json::to_value(request).expect("request should serialize"),
        json!({ "features": [] })
    );
}

#[test]
fn policy_get_can_request_an_exact_feature_subset() {
    let request = PolicyGetRequest::for_features(strings(&["clipboard.text", "files.send"]))
        .expect("feature filter should be valid");

    assert_eq!(request.features, strings(&["clipboard.text", "files.send"]));
}

#[test]
fn policy_get_rejects_duplicate_feature_filters() {
    let error = PolicyGetRequest::for_features(strings(&["files.send", "files.send"]))
        .expect_err("duplicate filters are ambiguous")
        .downcast_inner::<PolicyError>()
        .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::DuplicateIdentifier {
            field: "features",
            value: "files.send".to_owned(),
        }
    );
}

#[test]
fn policy_get_response_allows_an_empty_policy_store() {
    let response =
        PolicyGetResponse::new(0, Vec::new()).expect("an empty store is a valid get response");

    assert_eq!(response.revision, 0);
    assert!(response.policies.is_empty());
}

#[test]
fn policy_get_response_rejects_duplicate_feature_entries() {
    let error = PolicyGetResponse {
        revision: 4,
        policies: vec![allow("files.send"), deny("files.send")],
    }
    .validate()
    .expect_err("one response cannot contain two decisions for one feature")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::DuplicateFeature {
            field: "policies",
            feature: "files.send".to_owned(),
        }
    );
}

#[test]
fn policy_set_requires_at_least_one_change() {
    let error = PolicySetRequest::new(3, Vec::new())
        .expect_err("an empty policy.set request has no operation")
        .downcast_inner::<PolicyError>()
        .expect("policy error should be preserved");

    assert_eq!(error, PolicyError::EmptyChanges);
}

#[test]
fn policy_set_preserves_base_revision_and_changes() {
    let request = PolicySetRequest::new(7, vec![allow("clipboard.text"), limited("files.send")])
        .expect("policy.set request should be valid");
    let value = serde_json::to_value(&request).expect("request should serialize");

    assert_eq!(value["base_revision"], 7);
    assert_eq!(value["changes"].as_array().expect("changes array").len(), 2);
}

#[test]
fn policy_set_rejects_duplicate_changes() {
    let error = PolicySetRequest {
        base_revision: 1,
        changes: vec![allow("files.send"), deny("files.send")],
    }
    .validate()
    .expect_err("one request cannot set the same feature twice")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::DuplicateFeature {
            field: "changes",
            feature: "files.send".to_owned(),
        }
    );
}

#[test]
fn policy_rejection_serializes_safe_reason_and_limitations() {
    let rejection = PolicyRejection::new(
        "phone.screen.read",
        PolicyRejectionReason::CapabilityUnavailable,
        strings(&["media_projection_required"]),
    )
    .expect("rejection should be valid");
    let value = serde_json::to_value(&rejection).expect("rejection should serialize");

    assert_eq!(value["feature"], "phone.screen.read");
    assert_eq!(value["reason"], "capability_unavailable");
    assert_eq!(value["limitations"], json!(["media_projection_required"]));
}

#[test]
fn policy_set_response_can_mix_applied_and_rejected_features() {
    let response = PolicySetResponse::new(
        8,
        vec![limited("files.send")],
        vec![
            PolicyRejection::new(
                "phone.screen.read",
                PolicyRejectionReason::CapabilityUnavailable,
                strings(&["media_projection_required"]),
            )
            .expect("rejection should be valid"),
        ],
    )
    .expect("mixed response should be valid");

    assert_eq!(response.revision, 8);
    assert_eq!(response.applied.len(), 1);
    assert_eq!(response.rejected.len(), 1);
}

#[test]
fn policy_set_response_rejects_an_empty_result() {
    let error = PolicySetResponse {
        revision: 9,
        applied: Vec::new(),
        rejected: Vec::new(),
    }
    .validate()
    .expect_err("a set response must explain every requested change")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(error, PolicyError::EmptySetResponse);
}

#[test]
fn policy_set_response_rejects_a_feature_present_in_both_result_sections() {
    let error = PolicySetResponse {
        revision: 9,
        applied: vec![allow("files.send")],
        rejected: vec![
            PolicyRejection::new(
                "files.send",
                PolicyRejectionReason::RevisionConflict,
                Vec::new(),
            )
            .expect("rejection should be valid"),
        ],
    }
    .validate()
    .expect_err("a feature cannot be both applied and rejected")
    .downcast_inner::<PolicyError>()
    .expect("policy error should be preserved");

    assert_eq!(
        error,
        PolicyError::DuplicateFeature {
            field: "rejected",
            feature: "files.send".to_owned(),
        }
    );
}

#[test]
fn policy_rejection_limits_obey_batch_and_identifier_rules() {
    let rejection = PolicyRejection {
        feature: "files.send".to_owned(),
        reason: PolicyRejectionReason::InvalidChange,
        limitations: (0..=ProtocolLimits::default().max_batch_items())
            .map(|index| format!("restriction.{index}"))
            .collect(),
    };
    let error = rejection
        .validate()
        .expect_err("rejection limits must be bounded")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared batch limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::BatchTooLarge {
            field: "limitations",
            count: ProtocolLimits::default().max_batch_items() + 1,
            max: ProtocolLimits::default().max_batch_items(),
        }
    );
}

#[test]
fn policy_messages_do_not_serialize_secrets_or_paths() {
    let request = PolicySetRequest::new(
        1,
        vec![
            FeaturePolicy::new(
                "files.send",
                UserPolicyState::AllowLimited,
                strings(&["no_private_payloads"]),
                Some(1024),
                None,
            )
            .expect("policy should be valid"),
        ],
    )
    .expect("request should be valid");
    let encoded = serde_json::to_string(&request).expect("request should serialize");

    for forbidden in ["token", "secret", "private_key", "/home/", "../../"] {
        assert!(
            !encoded.contains(forbidden),
            "policy wire data unexpectedly contains forbidden marker {forbidden}"
        );
    }
}
