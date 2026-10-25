use std::sync::Arc;
use std::thread;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use peerbay_lib::app::AppRuntime;
use peerbay_lib::identity::{IdentityKeyPair, IdentityKeyStoreError};

use super::{PRIVATE_KEY_BYTES, key_store_error};

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
fn runtime_owns_one_transport_certificate_across_clones_and_startup() {
    let runtime = AppRuntime::new();
    let clone = runtime.clone();
    let certificate = runtime.transport_certificate();

    assert_eq!(certificate.device_id(), runtime.identity().device_id());
    assert_eq!(
        certificate.fingerprint(),
        clone.transport_certificate().fingerprint()
    );
    assert!(std::sync::Arc::ptr_eq(
        &certificate,
        &clone.transport_certificate()
    ));

    runtime.start().expect("runtime should start");
    assert_eq!(
        runtime.transport_certificate().fingerprint(),
        certificate.fingerprint()
    );
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
