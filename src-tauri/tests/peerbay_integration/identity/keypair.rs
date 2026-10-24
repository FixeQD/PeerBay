use std::panic::{AssertUnwindSafe, catch_unwind};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use peerbay_lib::identity::{IdentityKeyPair, IdentityKeyPairError};

use super::PRIVATE_KEY_BYTES;

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
        SigningKey::from_bytes(private_bytes)
            .sign(message)
            .to_bytes()
    });
    let verifying_key = VerifyingKey::from_bytes(&keypair.public_key_bytes())
        .expect("public key bytes should form a verifying key");

    verifying_key
        .verify(message, &Signature::from_bytes(&signature_bytes))
        .expect("signature made from private key should verify");
}

#[test]
fn private_key_debug_output_is_redacted_and_not_serialized() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let private_bytes = keypair.private_key_bytes();
    let debug = format!("{keypair:?} {private_bytes:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("7, 7, 7"));
    assert!(!debug.contains("private_key_bytes"));
}

#[test]
fn identity_keypair_rejects_no_mutation_of_public_material_via_private_callback() {
    let keypair = IdentityKeyPair::from_private_bytes(PRIVATE_KEY_BYTES);
    let before = keypair.public_key_bytes();

    keypair.with_private_key(|private_bytes| assert_eq!(private_bytes, &PRIVATE_KEY_BYTES));

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

    keypair
        .validate()
        .expect("arbitrary seed bytes should remain binary data");
    keypair.with_private_key(|bytes| assert_eq!(bytes, &private_bytes));
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
