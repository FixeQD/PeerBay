use peerbay_lib::identity::{IdentityKeyPair, IdentityKeyStore, IdentityKeyStoreError};

use super::{PRIVATE_KEY_BYTES, key_store_error};

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
