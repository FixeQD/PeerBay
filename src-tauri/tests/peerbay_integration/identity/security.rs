use uuid::Uuid;

use peerbay_lib::identity::{DeviceIdentity, DeviceIdentityError};

use super::{DEVICE_ID, identity_error};

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
