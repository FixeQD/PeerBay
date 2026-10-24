use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::thread;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::json;
use uuid::Uuid;

use peerbay_lib::app::AppRuntime;
use peerbay_lib::identity::{
    DeviceIdentity, DeviceIdentityError, IdentityKeyPair, IdentityKeyPairError, IdentityKeyStore,
    IdentityKeyStoreError, MAX_DEVICE_NAME_LENGTH,
};

const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const PRIVATE_KEY_BYTES: [u8; 32] = [7; 32];

fn identity_error(result: eros::Result<()>) -> DeviceIdentityError {
    result
        .expect_err("identity validation should fail")
        .downcast_inner::<DeviceIdentityError>()
        .expect("identity error should be preserved")
}

fn key_store_error(result: eros::Result<()>) -> IdentityKeyStoreError {
    result
        .expect_err("key store operation should fail")
        .downcast_inner::<IdentityKeyStoreError>()
        .expect("key store error should be preserved")
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

#[test]
fn generated_identity_keypair_has_a_valid_ed25519_public_key() {
    let keypair = IdentityKeyPair::generate();

    keypair
        .validate()
        .expect("generated keypair should validate");
    assert_eq!(keypair.public_key_bytes().len(), 32);
    assert!(!format!("{keypair:?}").contains("[7, 7, 7"));
}

#[test]
fn generated_identity_keypairs_are_distinct() {
    let first = IdentityKeyPair::generate();
    let second = IdentityKeyPair::generate();

    assert_ne!(first.public_key_bytes(), second.public_key_bytes());
}

#[test]
fn private_bytes_reconstruct_the_same_public_key_deterministically() {
    let first = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let second = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);

    assert_eq!(first.public_key_bytes(), second.public_key_bytes());
    first.validate().expect("first keypair should validate");
    second.validate().expect("second keypair should validate");
}

#[test]
fn private_key_callback_can_sign_but_does_not_return_a_persistent_reference() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let message = b"peerbay identity proof";
    let signature_bytes = keypair.with_private_key(|private_bytes| {
        let signing_key = SigningKey::from_bytes(private_bytes);
        signing_key.sign(message).to_bytes()
    });
    let verifying_key = VerifyingKey::from_bytes(&keypair.public_key_bytes())
        .expect("public key bytes should form a verifying key");
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(message, &signature)
        .expect("signature made from private key should verify");
}

#[test]
fn private_key_debug_output_is_redacted_and_not_serialized() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let private_bytes = keypair.private_key_bytes();
    let debug = format!("{keypair:?} {:?}", private_bytes);

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("7, 7, 7"));
    assert!(!debug.contains("private_key_bytes"));
}

#[test]
fn identity_key_store_starts_empty_and_reports_a_safe_error() {
    let store = IdentityKeyStore::new();

    assert!(store.is_empty());
    assert_eq!(
        key_store_error(store.load().map(|_| ())),
        IdentityKeyStoreError::MissingKeyPair
    );
}

#[test]
fn identity_key_store_saves_reads_takes_and_clears_without_serializing_secrets() {
    let mut store = IdentityKeyStore::new();
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let expected_public_key = keypair.public_key_bytes();

    store.save(keypair);
    assert!(!store.is_empty());
    assert_eq!(
        store.load().unwrap().public_key_bytes(),
        expected_public_key
    );
    assert!(format!("{:?}", store.load().unwrap()).contains("<redacted>"));

    let taken = store.take().expect("stored keypair should be takeable");
    assert_eq!(taken.public_key_bytes(), expected_public_key);
    assert!(store.is_empty());

    store.save(IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES));
    store.clear();
    assert!(store.is_empty());
}

#[test]
fn identity_key_store_replacing_a_keypair_exposes_only_the_new_public_key() {
    let mut store = IdentityKeyStore::generated();
    let replacement = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let expected_public_key = replacement.public_key_bytes();

    store.save(replacement);

    assert_eq!(
        store.load().unwrap().public_key_bytes(),
        expected_public_key
    );
}

#[test]
fn runtime_owns_keypair_across_clones_and_startup() {
    let runtime = AppRuntime::new();
    let clone = runtime.clone();
    let before_start = runtime.identity_public_key().expect("read public key");

    runtime.start().expect("runtime should start");
    assert_eq!(runtime.identity_public_key().unwrap(), before_start);
    assert_eq!(clone.identity_public_key().unwrap(), before_start);
    runtime.shutdown().expect("runtime should shut down");
}

#[test]
fn runtime_private_key_callback_matches_runtime_public_key() {
    let runtime = AppRuntime::new();
    let message = b"runtime identity proof";
    let signature_bytes = runtime
        .with_identity_private_key(|private_bytes| {
            SigningKey::from_bytes(private_bytes)
                .sign(message)
                .to_bytes()
        })
        .expect("private key callback should work");
    let verifying_key = VerifyingKey::from_bytes(&runtime.identity_public_key().unwrap())
        .expect("runtime public key should be valid");

    verifying_key
        .verify(message, &Signature::from_bytes(&signature_bytes))
        .expect("runtime keypair should verify its own signatures");
}

#[test]
fn runtime_can_replace_and_clear_keypair_without_affecting_device_identity() {
    let runtime = AppRuntime::new();
    let device_id = runtime.identity().device_id().to_owned();
    let replacement = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let expected_public_key = replacement.public_key_bytes();

    runtime
        .replace_identity_keypair(replacement)
        .expect("replacement should be stored");
    assert_eq!(runtime.identity_public_key().unwrap(), expected_public_key);
    assert_eq!(runtime.identity().device_id(), device_id);

    runtime
        .clear_identity_keypair()
        .expect("keypair should be clearable");
    assert_eq!(
        key_store_error(runtime.identity_public_key().map(|_| ())),
        IdentityKeyStoreError::MissingKeyPair
    );
    assert_eq!(runtime.identity().device_id(), device_id);
}

#[test]
fn identity_keypair_rejects_no_mutation_of_public_material_via_private_callback() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let before = keypair.public_key_bytes();

    keypair.with_private_key(|private_bytes| {
        assert_eq!(private_bytes, &PRIVATE_KEY_BYTES);
    });

    assert_eq!(keypair.public_key_bytes(), before);
    keypair.validate().expect("keypair should remain valid");
}

#[test]
fn identity_keypair_error_does_not_echo_private_bytes() {
    let error = IdentityKeyPairError::PublicKeyMismatch.to_string();

    assert!(!error.contains("7"));
    assert!(!error.contains(&format!("{:?}", PRIVATE_KEY_BYTES)));
}

#[test]
fn private_key_bytes_are_an_owned_zeroizing_copy_not_an_alias() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let private_bytes = keypair.private_key_bytes();
    let mut copied_bytes = *private_bytes.as_bytes();

    assert_eq!(copied_bytes, PRIVATE_KEY_BYTES);
    copied_bytes[0] ^= 0xff;

    assert_ne!(copied_bytes, PRIVATE_KEY_BYTES);
    keypair.with_private_key(|original| assert_eq!(original, &PRIVATE_KEY_BYTES));
    keypair
        .validate()
        .expect("mutating the copy must not corrupt keypair");
}

#[test]
fn keypair_accepts_binary_private_material_without_text_or_shell_interpretation() {
    let private_bytes = [
        0, 1, 2, 9, 10, 13, 27, 36, 59, 60, 62, 96, 124, 127, 128, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15,
    ];
    let keypair = IdentityKeyPair::from_private_bytes(private_bytes);
    let canary = format!("/tmp/peerbay-keypair-rce-{}", Uuid::new_v4().simple());

    keypair
        .validate()
        .expect("arbitrary seed bytes should remain binary data");
    keypair.with_private_key(|bytes| assert_eq!(bytes, &private_bytes));
    assert!(!std::path::Path::new(&canary).exists());
}

#[test]
fn all_zero_and_all_ff_private_seeds_are_valid_but_produce_distinct_keys() {
    let zero = IdentityKeyPair::from_private_bytes([0; 32]);
    let ff = IdentityKeyPair::from_private_bytes([0xff; 32]);

    zero.validate()
        .expect("zero seed is still a valid Ed25519 seed");
    ff.validate()
        .expect("ff seed is still a valid Ed25519 seed");
    assert_ne!(zero.public_key_bytes(), ff.public_key_bytes());
}

#[test]
fn deterministic_ed25519_signatures_verify_and_reject_modified_messages_or_signatures() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let message = b"identity message";
    let altered_message = b"identity messagE";
    let signature_bytes =
        keypair.with_private_key(|bytes| SigningKey::from_bytes(bytes).sign(message).to_bytes());
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&keypair.public_key_bytes()).expect("public key should be valid");

    verifying_key
        .verify(message, &signature)
        .expect("original signature should verify");
    assert!(verifying_key.verify(altered_message, &signature).is_err());

    let mut altered_signature_bytes = signature_bytes;
    altered_signature_bytes[0] ^= 0x01;
    assert!(
        verifying_key
            .verify(message, &Signature::from_bytes(&altered_signature_bytes))
            .is_err()
    );
}

#[test]
fn callback_panic_does_not_leave_the_keypair_invalid() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let result = catch_unwind(AssertUnwindSafe(|| {
        keypair.with_private_key(|bytes| {
            assert_eq!(bytes, &PRIVATE_KEY_BYTES);
            panic!("simulated storage adapter panic");
        });
    }));

    assert!(result.is_err());
    keypair.validate().expect("panic must not corrupt keypair");
    keypair.with_private_key(|bytes| assert_eq!(bytes, &PRIVATE_KEY_BYTES));
}

#[test]
fn key_store_repeated_save_clear_cycles_do_not_leave_a_stale_key_available() {
    let mut store = IdentityKeyStore::new();

    for value in 0u8..32 {
        let mut private_bytes = [0u8; 32];
        private_bytes.fill(value);
        store.save(IdentityKeyPair::from_private_bytes(private_bytes));
        assert!(store.load().is_ok());
        store.clear();
        assert!(store.is_empty());
        assert_eq!(
            key_store_error(store.load().map(|_| ())),
            IdentityKeyStoreError::MissingKeyPair
        );
    }
}

#[test]
fn runtime_clear_makes_both_public_and_private_reads_fail_without_changing_device_id() {
    let runtime = AppRuntime::new();
    let device_id = runtime.identity().device_id().to_owned();

    runtime
        .clear_identity_keypair()
        .expect("runtime keypair should clear");
    assert_eq!(
        key_store_error(runtime.identity_public_key().map(|_| ())),
        IdentityKeyStoreError::MissingKeyPair
    );
    assert_eq!(
        key_store_error(runtime.with_identity_private_key(|_| ())),
        IdentityKeyStoreError::MissingKeyPair
    );
    assert_eq!(runtime.identity().device_id(), device_id);
}

#[test]
fn runtime_concurrent_read_replace_and_clear_operations_do_not_panic_or_expose_invalid_lengths() {
    let runtime = Arc::new(AppRuntime::new());
    let mut handles = Vec::new();

    for reader_id in 0..6 {
        let runtime = Arc::clone(&runtime);
        handles.push(thread::spawn(move || {
            for iteration in 0..200 {
                if let Ok(public_key) = runtime.identity_public_key() {
                    assert_eq!(public_key.len(), 32);
                }
                if let Ok(private_key) = runtime.with_identity_private_key(|bytes| *bytes) {
                    assert_eq!(private_key.len(), 32);
                }
                if reader_id == 0 && iteration % 37 == 0 {
                    thread::yield_now();
                }
            }
        }));
    }

    let writer_runtime = Arc::clone(&runtime);
    handles.push(thread::spawn(move || {
        for iteration in 0u8..100 {
            let mut private_bytes = [0u8; 32];
            private_bytes.fill(iteration);
            writer_runtime
                .replace_identity_keypair(IdentityKeyPair::from_private_bytes(private_bytes))
                .expect("replacement should not fail");
            if iteration % 11 == 0 {
                writer_runtime
                    .clear_identity_keypair()
                    .expect("clear should not fail");
            }
        }
    }));

    for handle in handles {
        handle
            .join()
            .expect("concurrent key operations must not panic");
    }

    let _ = runtime.identity_public_key();
}

#[test]
fn missing_key_errors_do_not_include_paths_commands_or_private_material() {
    let store = IdentityKeyStore::new();
    let error = store
        .load()
        .expect_err("empty store should fail")
        .to_string();

    for forbidden in ["private_key", "secret", "/tmp", "$(id)", "touch", "sh"] {
        assert!(
            !error.contains(forbidden),
            "error leaked forbidden text: {forbidden}"
        );
    }
}
