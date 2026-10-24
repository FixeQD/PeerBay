use serde_json::json;
use uuid::Uuid;

use peerbay_lib::app::AppRuntime;
use peerbay_lib::identity::{DeviceIdentity, DeviceIdentityError, MAX_DEVICE_NAME_LENGTH};

const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

fn identity_error(result: eros::Result<()>) -> DeviceIdentityError {
    result
        .expect_err("identity validation should fail")
        .downcast_inner::<DeviceIdentityError>()
        .expect("identity error should be preserved")
}

#[test]
fn generated_identity_has_a_canonical_uuid_and_non_empty_display_name() {
    let identity = DeviceIdentity::generate();
    let parsed = Uuid::parse_str(identity.device_id()).unwrap();

    assert_eq!(parsed.to_string(), identity.device_id());
    assert_eq!(parsed.get_version_num(), 4);
    assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
    assert!(!identity.display_name().trim().is_empty());
    identity
        .validate()
        .expect("generated identity should validate");
}

#[test]
fn generated_identities_are_distinct() {
    let first = DeviceIdentity::generate();
    let second = DeviceIdentity::generate();

    assert_ne!(first.device_id(), second.device_id());
}

#[test]
fn loaded_identity_preserves_device_id_and_display_name() {
    let identity = DeviceIdentity::new(DEVICE_ID, "Test Phone").expect("identity should be valid");

    assert_eq!(identity.device_id(), DEVICE_ID);
    assert_eq!(identity.display_name(), "Test Phone");
}

#[test]
fn changing_display_name_does_not_rotate_device_id() {
    let identity = DeviceIdentity::new(DEVICE_ID, "Old Name").expect("identity should be valid");
    let renamed = identity
        .with_display_name("New Name")
        .expect("new display name should be valid");

    assert_eq!(renamed.device_id(), DEVICE_ID);
    assert_eq!(renamed.display_name(), "New Name");
}

#[test]
fn renaming_is_non_mutating_and_multiple_renames_keep_the_same_id() {
    let original = DeviceIdentity::new(DEVICE_ID, "Original").expect("identity should be valid");
    let renamed = original
        .with_display_name("First")
        .expect("first rename should be valid")
        .with_display_name("Second")
        .expect("second rename should be valid");

    assert_eq!(original.device_id(), DEVICE_ID);
    assert_eq!(original.display_name(), "Original");
    assert_eq!(renamed.device_id(), DEVICE_ID);
    assert_eq!(renamed.display_name(), "Second");
}

#[test]
fn identity_rejects_non_canonical_device_ids() {
    for value in [
        "",
        " ",
        "123E4567-E89B-12D3-A456-426614174000",
        "{123e4567-e89b-12d3-a456-426614174000}",
        "123e4567e89b12d3a456426614174000",
        "not-a-uuid",
        "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-426614174000\0",
    ] {
        let error = identity_error(DeviceIdentity::new(value, "Test Phone").map(|_| ()));
        assert!(matches!(
            error,
            DeviceIdentityError::InvalidDeviceId | DeviceIdentityError::InvalidDeviceIdFormat
        ));
    }
}

#[test]
fn identity_rejects_the_nil_uuid_to_prevent_colliding_default_identity() {
    assert_eq!(
        identity_error(
            DeviceIdentity::new("00000000-0000-0000-0000-000000000000", "Test Phone").map(|_| ())
        ),
        DeviceIdentityError::NilDeviceId
    );
}

#[test]
fn identity_rejects_empty_control_and_oversized_display_names() {
    assert_eq!(
        identity_error(DeviceIdentity::new(DEVICE_ID, "   ").map(|_| ())),
        DeviceIdentityError::EmptyDisplayName
    );
    assert_eq!(
        identity_error(DeviceIdentity::new(DEVICE_ID, "Phone\nName").map(|_| ())),
        DeviceIdentityError::DisplayNameControlCharacter
    );
    assert_eq!(
        identity_error(DeviceIdentity::new(DEVICE_ID, "x".repeat(129)).map(|_| ())),
        DeviceIdentityError::DisplayNameTooLong {
            length: 129,
            max: MAX_DEVICE_NAME_LENGTH,
        }
    );
}

#[test]
fn identity_rejects_surrounding_unicode_whitespace() {
    for value in [" Test Phone", "Test Phone ", "\u{2003}Test Phone"] {
        assert_eq!(
            identity_error(DeviceIdentity::new(DEVICE_ID, value).map(|_| ())),
            DeviceIdentityError::DisplayNameUnexpectedWhitespace
        );
    }
}

#[test]
fn identity_rejects_unicode_format_and_bidi_controls() {
    for value in [
        "Phone\u{200b}Name",
        "Phone\u{200d}Name",
        "Phone\u{202e}Name",
        "Phone\u{2066}Name",
        "Phone\u{feff}Name",
    ] {
        assert_eq!(
            identity_error(DeviceIdentity::new(DEVICE_ID, value).map(|_| ())),
            DeviceIdentityError::DisplayNameFormatCharacter
        );
    }
}

#[test]
fn identity_rejects_unicode_line_separators_that_can_break_log_or_script_contexts() {
    for value in ["Phone\u{2028}Name", "Phone\u{2029}Name"] {
        assert_eq!(
            identity_error(DeviceIdentity::new(DEVICE_ID, value).map(|_| ())),
            DeviceIdentityError::DisplayNameLineSeparator
        );
    }
}

#[test]
fn identity_accepts_normal_unicode_without_invisible_controls() {
    let identity = DeviceIdentity::new(DEVICE_ID, "Telefon Łódź 📱").expect("name should be valid");

    assert_eq!(identity.display_name(), "Telefon Łódź 📱");
}

#[test]
fn identity_accepts_exact_display_name_boundary_and_rejects_the_next_byte() {
    let exact = "x".repeat(MAX_DEVICE_NAME_LENGTH);
    let too_long = format!("{exact}x");

    DeviceIdentity::new(DEVICE_ID, exact).expect("exact byte boundary should be accepted");
    assert_eq!(
        identity_error(DeviceIdentity::new(DEVICE_ID, too_long).map(|_| ())),
        DeviceIdentityError::DisplayNameTooLong {
            length: MAX_DEVICE_NAME_LENGTH + 1,
            max: MAX_DEVICE_NAME_LENGTH,
        }
    );
}

#[test]
fn identity_uses_byte_limits_for_multibyte_names() {
    let valid = "é".repeat(MAX_DEVICE_NAME_LENGTH / 2);
    let invalid = format!("{valid}é");

    DeviceIdentity::new(DEVICE_ID, valid).expect("128 bytes should be accepted");
    assert_eq!(
        identity_error(DeviceIdentity::new(DEVICE_ID, invalid).map(|_| ())),
        DeviceIdentityError::DisplayNameTooLong {
            length: MAX_DEVICE_NAME_LENGTH + 2,
            max: MAX_DEVICE_NAME_LENGTH,
        }
    );
}

#[test]
fn identity_keeps_rce_like_names_as_opaque_data() {
    let payload = "$(touch /tmp/peerbay-identity-rce-canary); `id`; ../../secret; <script>";
    let identity = DeviceIdentity::new(DEVICE_ID, payload).expect("display names are data");
    let encoded = serde_json::to_string(&identity).expect("identity should serialize");
    let decoded: DeviceIdentity =
        serde_json::from_str(&encoded).expect("identity should deserialize");

    assert_eq!(decoded.display_name(), payload);
    assert!(encoded.contains("touch /tmp/peerbay-identity-rce-canary"));
    assert!(!std::path::Path::new("/tmp/peerbay-identity-rce-canary").exists());
}

#[test]
fn identity_rejects_terminal_escape_and_nul_payloads() {
    for value in ["Phone\u{1b}[2J", "Phone\0Name", "Phone\r\nName"] {
        assert_eq!(
            identity_error(DeviceIdentity::new(DEVICE_ID, value).map(|_| ())),
            DeviceIdentityError::DisplayNameControlCharacter
        );
    }
}

#[test]
fn identity_json_escaping_keeps_script_and_quote_payloads_literal() {
    let payload = "\"}; __proto__: null, <script>alert(1)</script>";
    let identity = DeviceIdentity::new(DEVICE_ID, payload).expect("display name should be data");
    let encoded = serde_json::to_string(&identity).expect("identity should serialize");
    let decoded: DeviceIdentity =
        serde_json::from_str(&encoded).expect("identity should deserialize");

    assert_eq!(decoded.display_name(), payload);
    assert!(encoded.contains("\\\"};"));
}

#[test]
fn identity_accepts_shell_metacharacters_only_as_literal_display_data() {
    for payload in [
        "$(id)",
        "`whoami`",
        "name; touch /tmp/pwned",
        "name && curl http://127.0.0.1/",
        "name | sh",
        "name > /tmp/pwned",
        "name && echo $HOME",
    ] {
        let identity =
            DeviceIdentity::new(DEVICE_ID, payload).expect("shell punctuation is display data");
        let encoded = serde_json::to_string(&identity).expect("identity should serialize");
        let decoded: DeviceIdentity =
            serde_json::from_str(&encoded).expect("identity should deserialize");

        assert_eq!(decoded.display_name(), payload);
    }
}

#[test]
fn identity_constructor_has_no_shell_side_effect_for_rce_payloads() {
    let canary = format!("/tmp/peerbay-identity-rce-{}", Uuid::new_v4().simple());
    let payload = format!("$(touch {canary})");
    let identity = DeviceIdentity::new(DEVICE_ID, payload.clone()).expect("identity is data");
    let _ = serde_json::to_string(&identity).expect("identity should serialize");

    assert_eq!(identity.display_name(), payload);
    assert!(!std::path::Path::new(&canary).exists());
}

#[test]
fn identity_deserialization_rejects_wrong_json_types_and_missing_fields() {
    for value in [
        json!({"device_id": 7, "display_name": "Test Phone"}),
        json!({"device_id": DEVICE_ID, "display_name": 7}),
        json!({"device_id": DEVICE_ID}),
        json!({"display_name": "Test Phone"}),
        json!(null),
        json!("device-id"),
    ] {
        assert!(serde_json::from_value::<DeviceIdentity>(value).is_err());
    }
}

#[test]
fn identity_deserialization_rejects_null_and_control_payloads_even_when_json_is_valid() {
    for value in [
        json!({
            "device_id": DEVICE_ID,
            "display_name": "Phone\nName"
        }),
        json!({
            "device_id": "00000000-0000-0000-0000-000000000000",
            "display_name": "Phone"
        }),
        json!({
            "device_id": DEVICE_ID,
            "display_name": "Phone\u{202e}Name"
        }),
    ] {
        assert!(serde_json::from_value::<DeviceIdentity>(value).is_err());
    }
}

#[test]
fn identity_deserialization_ignores_only_unknown_non_security_fields() {
    let value = json!({
        "device_id": DEVICE_ID,
        "display_name": "Test Phone",
        "future_identity_field": {"opaque": true}
    });

    let identity: DeviceIdentity =
        serde_json::from_value(value).expect("unknown optional fields should be ignored");
    assert_eq!(identity.device_id(), DEVICE_ID);
    assert_eq!(identity.display_name(), "Test Phone");
}

#[test]
fn identity_rejects_id_injection_attempts_before_uuid_parsing() {
    for value in [
        "123e4567-e89b-12d3-a456-426614174000\nwhoami",
        "123e4567-e89b-12d3-a456-426614174000;touch /tmp/pwned",
        "$(id)",
        "../../etc/passwd",
    ] {
        let error = identity_error(DeviceIdentity::new(value, "Test Phone").map(|_| ()));
        assert_eq!(error, DeviceIdentityError::InvalidDeviceIdFormat);
    }
}

#[test]
fn identity_error_messages_do_not_echo_untrusted_payloads() {
    let payload = "$(touch /tmp/secret);\nvery-private-name";
    let error = DeviceIdentity::new(DEVICE_ID, payload)
        .expect_err("control characters must be rejected")
        .to_string();

    assert!(!error.contains(payload));
    assert!(!error.contains("/tmp/secret"));
    assert!(!error.contains("very-private-name"));
}

#[test]
fn identity_roundtrips_through_json_without_changing_wire_fields() {
    let identity = DeviceIdentity::new(DEVICE_ID, "Test Phone").expect("identity should be valid");
    let encoded = serde_json::to_value(&identity).expect("identity should serialize");

    assert_eq!(
        encoded,
        json!({
            "device_id": DEVICE_ID,
            "display_name": "Test Phone"
        })
    );

    let decoded: DeviceIdentity =
        serde_json::from_value(encoded).expect("identity should deserialize");
    assert_eq!(decoded, identity);
}

#[test]
fn identity_deserialization_revalidates_untrusted_values() {
    let invalid = json!({
        "device_id": "123E4567-E89B-12D3-A456-426614174000",
        "display_name": "Test Phone"
    });

    assert!(serde_json::from_value::<DeviceIdentity>(invalid).is_err());
}

#[test]
fn app_runtime_keeps_one_identity_across_clones_and_startup() {
    let runtime = AppRuntime::new();
    let clone = runtime.clone();
    let before_start = runtime.identity();

    runtime.start().expect("runtime should start");
    let after_start = runtime.identity();

    assert_eq!(before_start, after_start);
    assert_eq!(clone.identity(), before_start);
    runtime.shutdown().expect("runtime should shut down");
}
