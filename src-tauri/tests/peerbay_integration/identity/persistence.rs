use std::panic::{AssertUnwindSafe, catch_unwind};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Value, json};
use uuid::Uuid;

use peerbay_lib::app::AppRuntime;
use peerbay_lib::identity::{
    DeviceIdentity, DeviceIdentityError, IdentityKeyPair, IdentityKeyStoreError,
    TransportCertificate,
};

use super::{DEVICE_ID, PRIVATE_KEY_BYTES, identity_error, key_store_error};

fn decode_identity(bytes: &[u8]) -> Result<DeviceIdentity, serde_json::Error> {
    serde_json::from_slice(bytes)
}

fn assert_identity_store_rejects(bytes: &[u8]) {
    assert!(
        decode_identity(bytes).is_err(),
        "corrupt identity store payload unexpectedly decoded: {bytes:?}"
    );
}

#[test]
fn persisted_identity_roundtrip_preserves_id_name_and_wire_bytes() {
    let identity =
        DeviceIdentity::new(DEVICE_ID, "Test Phone 📱").expect("identity should be valid");
    let first = serde_json::to_vec(&identity).expect("identity should serialize");
    let restored = decode_identity(&first).expect("identity should restore");
    let second = serde_json::to_vec(&restored).expect("restored identity should serialize");

    assert_eq!(restored, identity);
    assert_eq!(restored.device_id(), DEVICE_ID);
    assert_eq!(restored.display_name(), "Test Phone 📱");
    assert_eq!(first, second);
}

#[test]
fn repeated_identity_store_roundtrips_are_idempotent() {
    let mut bytes = serde_json::to_vec(
        &DeviceIdentity::new(DEVICE_ID, "Roundtrip Device").expect("identity should be valid"),
    )
    .expect("identity should serialize");

    for _ in 0..128 {
        let identity = decode_identity(&bytes).expect("identity should restore repeatedly");
        let next = serde_json::to_vec(&identity).expect("identity should serialize repeatedly");
        assert_eq!(next, bytes);
        bytes = next;
    }
}

#[test]
fn persisted_generated_identity_keeps_canonical_uuid_v4_after_restore() {
    let identity = DeviceIdentity::generate();
    let restored = decode_identity(
        &serde_json::to_vec(&identity).expect("generated identity should serialize"),
    )
    .expect("generated identity should restore");
    let parsed = Uuid::parse_str(restored.device_id()).expect("restored ID should be a UUID");

    assert_eq!(parsed.to_string(), restored.device_id());
    assert_eq!(parsed.get_version_num(), 4);
    assert_eq!(parsed.get_variant(), uuid::Variant::RFC4122);
    restored
        .validate()
        .expect("restored identity should validate");
}

#[test]
fn display_name_rotation_is_explicit_and_never_rotates_device_id() {
    let original = DeviceIdentity::new(DEVICE_ID, "Original").expect("identity should be valid");
    let mut current = original.clone();

    for name in ["First", "Second", "Final Device 📱"] {
        current = current
            .with_display_name(name)
            .expect("display name rotation should validate");
        let restored = decode_identity(
            &serde_json::to_vec(&current).expect("rotated identity should serialize"),
        )
        .expect("rotated identity should restore");

        assert_eq!(restored.device_id(), DEVICE_ID);
        assert_eq!(restored.display_name(), name);
    }

    assert_eq!(original.device_id(), DEVICE_ID);
    assert_eq!(original.display_name(), "Original");
}

#[test]
fn identity_id_changes_only_when_a_new_identity_is_explicitly_generated() {
    let persisted = DeviceIdentity::new(DEVICE_ID, "Persisted").expect("identity should be valid");
    let restored =
        decode_identity(&serde_json::to_vec(&persisted).expect("identity should serialize"))
            .expect("identity should restore");
    let generated = DeviceIdentity::generate();

    assert_eq!(restored.device_id(), persisted.device_id());
    assert_ne!(generated.device_id(), persisted.device_id());
}

#[test]
fn identity_store_accepts_future_non_security_fields_without_changing_identity() {
    let canary = format!(
        "/tmp/peerbay-persistence-future-{}",
        Uuid::new_v4().simple()
    );
    let payload = json!({
        "device_id": DEVICE_ID,
        "display_name": "Future-compatible",
        "schema_version": 999,
        "last_seen_at": format!("$(touch {canary})"),
        "metadata": {"command": "`id`", "path": "../../secret"}
    });
    let restored: DeviceIdentity =
        serde_json::from_value(payload).expect("future fields are opaque");

    assert_eq!(restored.device_id(), DEVICE_ID);
    assert_eq!(restored.display_name(), "Future-compatible");
    assert!(!std::path::Path::new(&canary).exists());
}

#[test]
fn identity_store_rejects_truncated_empty_and_trailing_payloads() {
    for bytes in [
        b"".as_slice(),
        b" ".as_slice(),
        b"{\"device_id\":\"123e4567-e89b-12d3-a456-426614174000\"".as_slice(),
        b"{\"device_id\":\"123e4567-e89b-12d3-a456-426614174000\",\"display_name\":\"Phone\"} trailing".as_slice(),
        b"{\"device_id\":\"123e4567-e89b-12d3-a456-426614174000\",\"display_name\":\"Phone\"}{}".as_slice(),
    ] {
        assert_identity_store_rejects(bytes);
    }
}

#[test]
fn identity_store_rejects_wrong_shapes_types_and_duplicate_security_fields() {
    let payloads: [Value; 10] = [
        Value::Null,
        json!([]),
        json!("identity"),
        json!({"device_id": 7, "display_name": "Phone"}),
        json!({"device_id": DEVICE_ID, "display_name": 7}),
        json!({"device_id": DEVICE_ID}),
        json!({"display_name": "Phone"}),
        json!({"device_id": null, "display_name": "Phone"}),
        json!({"device_id": DEVICE_ID, "display_name": null}),
        json!({"device_id": [DEVICE_ID], "display_name": ["Phone"]}),
    ];

    for payload in payloads {
        assert_identity_store_rejects(
            &serde_json::to_vec(&payload).expect("malformed fixture should serialize"),
        );
    }

    for bytes in [
        br#"{"device_id":"123e4567-e89b-12d3-a456-426614174000","device_id":"other","display_name":"Phone"}"#
            .as_slice(),
        br#"{"device_id":"123e4567-e89b-12d3-a456-426614174000","display_name":"Phone","display_name":"other"}"#
            .as_slice(),
    ] {
        assert_identity_store_rejects(bytes);
    }
}

#[test]
fn identity_store_rejects_noncanonical_and_dangerous_device_ids() {
    for device_id in [
        "",
        " ",
        "123E4567-E89B-12D3-A456-426614174000",
        "{123e4567-e89b-12d3-a456-426614174000}",
        "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-426614174000\nwhoami",
        "123e4567-e89b-12d3-a456-426614174000;touch /tmp/pwned",
        "$(id)",
        "../../etc/passwd",
        "00000000-0000-0000-0000-000000000000",
    ] {
        let bytes = serde_json::to_vec(&json!({
            "device_id": device_id,
            "display_name": "Phone"
        }))
        .expect("fixture should serialize");
        assert_identity_store_rejects(&bytes);
    }
}

#[test]
fn identity_store_rejects_dangerous_display_names_without_executing_them() {
    let canary = format!("/tmp/peerbay-persistence-rce-{}", Uuid::new_v4().simple());
    for display_name in [
        "",
        "   ",
        "Phone\nName",
        "Phone\0Name",
        "Phone\u{1b}[2J",
        "Phone\u{202e}Name",
        "Phone\u{2028}Name",
        " Phone",
        "Phone ",
    ] {
        let bytes = serde_json::to_vec(&json!({
            "device_id": DEVICE_ID,
            "display_name": display_name
        }))
        .expect("fixture should serialize");
        assert_identity_store_rejects(&bytes);
    }

    let rce_name = format!("$(touch {canary})");
    let bytes = serde_json::to_vec(&json!({
        "device_id": DEVICE_ID,
        "display_name": rce_name
    }))
    .expect("RCE fixture should serialize");
    let restored = decode_identity(&bytes).expect("shell punctuation remains display data");

    assert!(!std::path::Path::new(&canary).exists());
    assert_eq!(restored.display_name(), format!("$(touch {canary})"));
}

#[test]
fn identity_store_rejects_multibyte_names_over_the_byte_limit() {
    let over_limit = format!("{}é", "é".repeat(64));
    let bytes = serde_json::to_vec(&json!({
        "device_id": DEVICE_ID,
        "display_name": over_limit
    }))
    .expect("fixture should serialize");

    assert_identity_store_rejects(&bytes);
    assert_eq!(
        identity_error(DeviceIdentity::new(DEVICE_ID, over_limit).map(|_| ())),
        DeviceIdentityError::DisplayNameTooLong {
            length: 130,
            max: 128,
        }
    );
}

#[test]
fn identity_store_handles_invalid_utf8_and_invalid_escape_bytes_without_panicking() {
    let invalid_utf8 =
        b"{\"device_id\":\"123e4567-e89b-12d3-a456-426614174000\",\"display_name\":\"\xff\"}";
    let invalid_escape =
        b"{\"device_id\":\"123e4567-e89b-12d3-a456-426614174000\",\"display_name\":\"\\uD800\"}";

    for bytes in [invalid_utf8.as_slice(), invalid_escape.as_slice()] {
        let result = catch_unwind(AssertUnwindSafe(|| decode_identity(bytes)));
        assert!(result.is_ok(), "malformed bytes must not panic");
        assert!(result.expect("catch_unwind should return").is_err());
    }
}

#[test]
fn identity_store_mutation_corpus_never_panics_and_never_accepts_invalid_identity() {
    let original = serde_json::to_vec(
        &DeviceIdentity::new(DEVICE_ID, "Mutation Corpus").expect("identity should be valid"),
    )
    .expect("identity should serialize");

    for index in 0..original.len() {
        for mask in [0x01, 0x20, 0x80, 0xff] {
            let mut mutated = original.clone();
            mutated[index] ^= mask;
            let result = catch_unwind(AssertUnwindSafe(|| decode_identity(&mutated)));
            assert!(result.is_ok(), "mutated store bytes must not panic");
            if let Ok(Ok(identity)) = result {
                identity
                    .validate()
                    .expect("accepted mutated identity must still validate");
            }
        }
    }
}

#[test]
fn identity_store_rejects_large_security_fields_instead_of_restoring_them() {
    let huge_name = "x".repeat(256 * 1024);
    let bytes = serde_json::to_vec(&json!({
        "device_id": DEVICE_ID,
        "display_name": huge_name
    }))
    .expect("large fixture should serialize");

    assert_identity_store_rejects(&bytes);
}

#[test]
fn persisted_identity_wire_shape_contains_no_key_or_certificate_material() {
    let identity =
        DeviceIdentity::new(DEVICE_ID, "Public Metadata").expect("identity should be valid");
    let value = serde_json::to_value(identity).expect("identity should serialize");
    let object = value
        .as_object()
        .expect("identity should serialize as an object");

    assert_eq!(object.len(), 2);
    assert!(object.contains_key("device_id"));
    assert!(object.contains_key("display_name"));
    for forbidden in [
        "private_key",
        "private_key_der",
        "secret",
        "certificate",
        "certificate_der",
        "fingerprint",
    ] {
        assert!(
            !object.contains_key(forbidden),
            "wire leaked field {forbidden}"
        );
    }
}

#[test]
fn malformed_identity_store_errors_do_not_echo_private_or_command_payloads() {
    let payload = "$(touch /tmp/private-canary); secret-name; ../../private-path";
    let bytes = serde_json::to_vec(&json!({
        "device_id": DEVICE_ID,
        "display_name": format!("Phone\n{payload}")
    }))
    .expect("fixture should serialize");
    let error = decode_identity(&bytes)
        .expect_err("control payload should be rejected")
        .to_string();

    assert!(!error.contains(payload));
    assert!(!error.contains("/tmp/private-canary"));
    assert!(!error.contains("private-path"));
}

#[test]
fn keypair_persistence_roundtrip_reconstructs_same_public_identity() {
    let original = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let persisted_private = original.private_key_bytes();
    let restored = IdentityKeyPair::from_private_bytes(*persisted_private.as_bytes());

    assert_eq!(restored.public_key_bytes(), original.public_key_bytes());
    restored
        .validate()
        .expect("restored keypair should validate");
}

#[test]
fn keypair_rotation_changes_public_identity_but_not_device_id() {
    let runtime = AppRuntime::new();
    let device_id = runtime.identity().device_id().to_owned();
    let first = IdentityKeyPair::from_private_bytes([7; 32]);
    let second = IdentityKeyPair::from_private_bytes([8; 32]);

    runtime
        .replace_identity_keypair(first)
        .expect("first keypair should be accepted");
    let first_public = runtime
        .identity_public_key()
        .expect("first public key should load");
    runtime
        .replace_identity_keypair(second)
        .expect("rotated keypair should be accepted");
    let second_public = runtime
        .identity_public_key()
        .expect("rotated public key should load");

    assert_ne!(first_public, second_public);
    assert_eq!(runtime.identity().device_id(), device_id);
    assert_eq!(runtime.transport_certificate().device_id(), device_id);
}

#[test]
fn keypair_rotation_drops_old_private_material_and_clear_drops_current_material() {
    let runtime = AppRuntime::new();
    let old = IdentityKeyPair::from_private_bytes([7; 32]);
    let new = IdentityKeyPair::from_private_bytes([8; 32]);

    runtime
        .replace_identity_keypair(old)
        .expect("old keypair should be accepted");
    runtime
        .replace_identity_keypair(new)
        .expect("new keypair should replace old keypair");
    assert_eq!(
        runtime
            .with_identity_private_key(|bytes| *bytes)
            .expect("new private material should be available"),
        [8; 32]
    );

    runtime
        .clear_identity_keypair()
        .expect("clear should remove current keypair");
    assert_eq!(
        key_store_error(runtime.with_identity_private_key(|_| ())),
        IdentityKeyStoreError::MissingKeyPair
    );
}

#[test]
fn keypair_rotation_invalidates_signatures_from_the_previous_key() {
    let runtime = AppRuntime::new();
    let old = IdentityKeyPair::from_private_bytes([7; 32]);
    let new = IdentityKeyPair::from_private_bytes([8; 32]);
    let message = b"rotation-bound identity proof";

    runtime
        .replace_identity_keypair(old)
        .expect("old keypair should be accepted");
    let old_signature = runtime
        .with_identity_private_key(|bytes| SigningKey::from_bytes(bytes).sign(message).to_bytes())
        .expect("old signature should be produced");
    let old_public = runtime
        .identity_public_key()
        .expect("old public key should load");

    runtime
        .replace_identity_keypair(new)
        .expect("new keypair should be accepted");
    let new_public = runtime
        .identity_public_key()
        .expect("new public key should load");
    let old_verifier = VerifyingKey::from_bytes(&old_public).expect("old public key should parse");
    let new_verifier = VerifyingKey::from_bytes(&new_public).expect("new public key should parse");
    let signature = Signature::from_bytes(&old_signature);

    old_verifier
        .verify(message, &signature)
        .expect("old signature should match old public key");
    assert!(new_verifier.verify(message, &signature).is_err());
}

#[test]
fn repeated_keypair_rotation_and_clear_cycles_never_resurrect_old_keys() {
    let runtime = AppRuntime::new();

    for value in 0u8..64 {
        runtime
            .replace_identity_keypair(IdentityKeyPair::from_private_bytes([value; 32]))
            .expect("rotation should succeed");
        assert_eq!(
            runtime
                .with_identity_private_key(|bytes| *bytes)
                .expect("current key should load"),
            [value; 32]
        );
        runtime
            .clear_identity_keypair()
            .expect("clear should succeed");
        assert_eq!(
            key_store_error(runtime.identity_public_key().map(|_| ())),
            IdentityKeyStoreError::MissingKeyPair
        );
    }
}

#[test]
fn transport_certificate_rotation_preserves_device_binding_but_changes_fingerprint() {
    let first = TransportCertificate::generate_for_device(DEVICE_ID)
        .expect("first certificate should generate");
    let second = TransportCertificate::generate_for_device(DEVICE_ID)
        .expect("rotated certificate should generate");

    assert_eq!(first.device_id(), DEVICE_ID);
    assert_eq!(second.device_id(), DEVICE_ID);
    assert_ne!(first.fingerprint(), second.fingerprint());
    first
        .validate()
        .expect("old certificate should remain valid");
    second
        .validate()
        .expect("new certificate should remain valid");
}

#[test]
fn certificate_rotation_does_not_follow_a_changed_device_id() {
    let certificate =
        TransportCertificate::generate_for_device(DEVICE_ID).expect("certificate should generate");
    let other_id = "123e4567-e89b-12d3-a456-426614174001";

    assert_eq!(certificate.device_id(), DEVICE_ID);
    assert_ne!(certificate.device_id(), other_id);
    assert!(
        !certificate
            .certificate_der()
            .windows(other_id.len())
            .any(|window| window == other_id.as_bytes())
    );
}
