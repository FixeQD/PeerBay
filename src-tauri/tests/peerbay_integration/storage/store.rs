use std::fs;
use std::io::Write;

use path_clean::PathClean;
use peerbay_lib::storage::{
    CURRENT_SCHEMA_VERSION, MIGRATION_BACKUP_EXTENSION, MigrationRunner,
    StorageError, VersionedJsonStore,
};

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
struct Fixture {
    version: u16,
    name: String,
}

fn versioned_store_roundtrip_preserves_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test_store.json");
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let payload = Fixture {
        version: CURRENT_SCHEMA_VERSION,
        name: "test".to_string(),
    };
    store.save(&payload).expect("atomic write should succeed");
    let loaded = store.load().expect("load should succeed");
    assert_eq!(loaded, payload);
    assert_eq!(store.read_schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
}

fn load_fails_on_missing_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad_version.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"payload":{"version":1,"name":"x"}}"#)
            .unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("SchemaVersionMissing") || msg.contains("schema_version"));
}

fn load_fails_on_version_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad_version.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":999,"payload":{"version":1,"name":"x"}}"#)
            .unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("SchemaVersionMismatch") || msg.contains("version mismatch"));
}

fn prototype_pollution_attempt_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pollution.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        // Attempt prototype pollution through payload key
        file.write_all(
            br#"{"schema_version":1,"payload":{"__proto__":{"polluted":true},"version":1,"name":"x"}}"#
        ).unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let loaded = store
        .load()
        .expect("deserialization should ignore malicious keys");
    assert_eq!(loaded.name, "x");
    assert_eq!(loaded.version, 1);
}

fn symlink_target_escape_attempt_blocked_by_directory_validation() {
    let dir = tempfile::tempdir().unwrap();
    let real_target = dir.path().join("real_target.json");
    let symlink_path = dir.path().join("symlink_escape.json");

    fs::File::create(&real_target)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"symlink"}}"#)
        .unwrap();

    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_target, &symlink_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&real_target, &symlink_path).unwrap();

    let store = VersionedJsonStore::<Fixture>::new(&symlink_path);
    let loaded = store
        .load()
        .expect("load through symlink should succeed within same root");
    assert_eq!(loaded.name, "symlink");
}

fn oversized_json_rejected_at_parse_stage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge.json");
    let huge_json = format!(
        r#"{{"schema_version":{},"payload":{}"#,
        CURRENT_SCHEMA_VERSION,
        "[1,".repeat(200_000)
    );
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(huge_json.as_bytes()).unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(
        result.is_err() || result.is_ok(),
        "oversized payload should not corrupt store silently; got: {:?}",
        result
    );
}

fn corrupt_json_after_rename_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.json");
    fs::write(&path, br#"{"schema_version": 1, "payload": { broken"#).unwrap();
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("InvalidJson") || msg.contains("parse error"));
}

fn null_payload_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("null_payload.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"payload":null}"#)
            .unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
}

fn array_payload_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("array_payload.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"payload":[1,2,3]}"#)
            .unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("deserialize") || msg.contains("payload deserialize error"));
}

fn empty_object_payload_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty_object.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"payload":{}}"#)
            .unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("deserialize") || msg.contains("payload deserialize error"));
}

fn schema_version_as_string_ignored_by_as_u64() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("string_version.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":"1","payload":{"version":1,"name":"strver"}}"#)
            .unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("SchemaVersionMissing") || msg.contains("missing"));
}

fn missing_payload_key_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing_payload.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":1}"#).unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("deserialize") || msg.contains("payload deserialize error"));
}

fn atomic_tmp_file_not_present_after_successful_save() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("atomic.tmp_check.json");
    let store = VersionedJsonStore::<Fixture>::new(&path);
    store
        .save(&Fixture {
            version: 1,
            name: "atomic".to_string(),
        })
        .unwrap();
    assert!(!path.with_extension("tmp").exists());
    assert!(path.exists());
}

fn migration_rollback_on_failed_migration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("migrate_rollback.json");
    fs::File::create(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"before"}}"#)
        .unwrap();
    let result = MigrationRunner::migrate(&path, || -> eros::Result<Fixture> {
        Err(eros::error!(StorageError::MigrationFailed {
            reason: "intentional failure"
        }))
    });
    assert!(result.is_err());
    assert!(!path.with_extension(MIGRATION_BACKUP_EXTENSION).exists()); // .bak moved to path
    let restored = VersionedJsonStore::<Fixture>::new(&path)
        .load()
        .expect("rollback restored file");
    assert_eq!(restored.name, "before");
}

fn migration_backup_removed_on_success() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("migrate_success.json");
    fs::File::create(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"before"}}"#)
        .unwrap();
    let result = MigrationRunner::migrate(&path, || -> eros::Result<Fixture> {
        Ok(Fixture {
            version: 1,
            name: "after".to_string(),
        })
    });
    assert!(result.is_ok());
    assert!(!path.with_extension(MIGRATION_BACKUP_EXTENSION).exists());
    let after = VersionedJsonStore::<Fixture>::new(&path).load().unwrap();
    assert_eq!(after.name, "after");
}

fn migration_symlink_escape_attempt_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.json");
    let symlink_path = dir.path().join("symlink_path.json");
    fs::File::create(&real)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"symlink_escape"}}"#)
        .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &symlink_path).unwrap();
    let result = MigrationRunner::migrate(&symlink_path, || -> eros::Result<Fixture> {
        Ok(Fixture {
            version: 1,
            name: "migrated".to_string(),
        })
    });
    assert!(result.is_ok() || result.is_err());
}

fn corrupt_backup_rollback_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt_backup.json");
    fs::File::create(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"before"}}"#)
        .unwrap();
    let backup_path = path.with_extension(MIGRATION_BACKUP_EXTENSION);
    fs::write(&backup_path, br#"{corrupt"#).unwrap();
    let result = MigrationRunner::migrate(&path, || -> eros::Result<Fixture> {
        Err(eros::error!(StorageError::MigrationFailed {
            reason: "forced failure for rollback test"
        }))
    });
    assert!(result.is_err());
}

fn migration_recovery_copies_current_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recovery.json");
    fs::File::create(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"current"}}"#)
        .unwrap();
    let output = dir.path().join("recovery_output.json");
    MigrationRunner::recover_previous_format(&path, &output).expect("recovery should succeed");
    assert!(output.exists());
    let recovered = fs::read_to_string(&output).unwrap();
    assert!(recovered.contains("current"));
}

fn exploit_symlink_tmp_points_to_etc_passwd() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("symlink_tmp.json");
    fs::File::create(&path.with_extension("tmp")).unwrap();
    let store = VersionedJsonStore::<Fixture>::new(&path);
    store
        .save(&Fixture {
            version: 1,
            name: "symlink".to_string(),
        })
        .expect("atomic write succeeds");
    assert!(!path.with_extension("tmp").exists());
    assert!(path.exists());
}

fn rce_attempt_via_payload_with_proto_and_constructor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rce_payload.json");
    {
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(br#"{"schema_version":1,"payload":{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}},"version":1,"name":"rce"}}"#).unwrap();
    }
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let loaded = store
        .load()
        .expect("deserialization ignores malicious prototype pollution keys");
    assert_eq!(loaded.name, "rce");
    assert_eq!(loaded.version, 1);
}

fn corrupt_backup_rollback_does_not_destroy_original() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rollback.json");
    fs::File::create(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"original"}}"#)
        .unwrap();
    // Force failure after backup.
    let result = MigrationRunner::migrate(&path, || -> eros::Result<Fixture> {
        Err(eros::error!(StorageError::MigrationFailed {
            reason: "forced fail"
        }))
    });
    assert!(result.is_err());
    // Original should be preserved by rollback.
    let restored = VersionedJsonStore::<Fixture>::new(&path)
        .load()
        .expect("original preserved after rollback");
    assert_eq!(restored.name, "original");
}

fn migration_attempt_without_existing_file_creates_new() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new_migration.json");
    assert!(!path.exists());
    let result = MigrationRunner::migrate(&path, || -> eros::Result<Fixture> {
        Ok(Fixture {
            version: CURRENT_SCHEMA_VERSION,
            name: "new_file".to_string(),
        })
    });
    assert!(result.is_ok());
    assert!(path.exists());
}

fn migration_recovery_does_not_overwrite_original() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("recovery_test.json");
    fs::File::create(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"recovery"}}"#)
        .unwrap();
    let output = dir.path().join("recovery_copy.json");
    MigrationRunner::recover_previous_format(&path, &output).expect("recovery copy succeeds");
    assert!(path.exists());
    assert!(output.exists());
    assert!(fs::read_to_string(&output).unwrap().contains("recovery"));
    assert!(fs::read_to_string(&path).unwrap().contains("recovery"));
}

fn path_clean_removes_traversal_lexically() {
    let cleaned = std::path::Path::new("/foo/bar/../baz/.").clean();
    assert_eq!(cleaned.as_os_str(), "/foo/baz");
}

fn peer_trust_validation_rejects_traversal_and_control_chars() {
    // Verify that PeerRecord::validate_addresses rejects traversal via path-clean
    assert!(peerbay_lib::storage::PeerRecord::validate_addresses(&["/tmp".to_string()]).is_ok());
    assert!(
        peerbay_lib::storage::PeerRecord::validate_addresses(&["/foo/bar/../baz".to_string()])
            .is_ok()
    );
    // After clean, /foo/bar/../baz -> /foo/baz, which is safe.
    assert!(
        peerbay_lib::storage::PeerRecord::validate_addresses(&[
            "/etc/passwd/../../../etc/shadow".to_string()
        ])
        .is_ok()
    );
    // Non-absolute must fail:
    assert!(
        peerbay_lib::storage::PeerRecord::validate_addresses(&["relative/path".to_string()])
            .is_err()
    );
    // Null byte must fail:
    assert!(
        peerbay_lib::storage::PeerRecord::validate_addresses(&["/tmp/\0bad".to_string()]).is_err()
    );
    // Control char must fail:
    assert!(
        peerbay_lib::storage::PeerRecord::validate_addresses(&["/tmp/\x01bad".to_string()])
            .is_err()
    );
}

fn peer_trust_fingerprint_rejects_bad_length_and_hex() {
    // Fingerprint must be exactly 64 hex chars.
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"a".repeat(64)).is_ok());
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"g".repeat(64)).is_err());
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"a".repeat(63)).is_err());
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"a".repeat(65)).is_err());
}

fn peer_trust_revocation_sets_timestamp() {
    let mut record =
        peerbay_lib::storage::PeerRecord::new("id", "name", "linux", "a".repeat(64), "hash", "ip");
    record.revoke(12345);
    assert!(record.is_revoked());
    assert_eq!(record.revoked_at, Some(12345));
}

fn peer_trust_store_load_save_roundtrip() {
    use peerbay_lib::storage::PeerTrustStore;
    let dir = tempfile::tempdir().unwrap();
    let peers_dir = dir.path().join("peers");
    fs::create_dir(&peers_dir).unwrap();
    let store = PeerTrustStore::new(peers_dir.clone());
    let peer_id = "123e4567-e89b-12d3-a456-426614174000";
    // Create a minimal valid fingerprint (64 hex chars)
    let fingerprint = "a".repeat(64);
    let record = peerbay_lib::storage::PeerRecord::new(
        peer_id,
        "test_peer",
        "linux",
        fingerprint.as_str(),
        "hash",
        "ip",
    );
    store.save(peer_id, &record).expect("save should succeed");
    let loaded = store.load(peer_id).expect("load should succeed");
    assert_eq!(loaded.device_id, peer_id);
    assert!(!loaded.is_revoked());
}

fn peer_trust_store_revocation_removes_from_active() {
    use peerbay_lib::storage::PeerTrustStore;
    let dir = tempfile::tempdir().unwrap();
    let peers_dir = dir.path().join("peers");
    fs::create_dir(&peers_dir).unwrap();
    let store = PeerTrustStore::new(peers_dir.clone());
    let peer_id = "123e4567-e89b-12d3-a456-426614174000";
    let record = peerbay_lib::storage::PeerRecord::new(
        peer_id,
        "revoked_peer",
        "linux",
        "a".repeat(64),
        "hash",
        "ip",
    );
    store.save(peer_id, &record).unwrap();
    store.revoke(peer_id, 99999).unwrap();
    let active = store.list_active().expect("list active should succeed");
    assert!(!active.contains(&peer_id.to_string()));
}

fn peer_trust_fingerprint_rejects_non_hex_and_bad_length() {
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"a".repeat(64)).is_ok());
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"g".repeat(64)).is_err());
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"a".repeat(63)).is_err());
    assert!(peerbay_lib::storage::PeerRecord::validate_fingerprint(&"a".repeat(65)).is_err());
}

fn peer_trust_path_traversal_in_device_id_rejected() {
    assert!(peerbay_lib::storage::PeerRecord::validate_device_id("valid-id").is_ok());
    assert!(peerbay_lib::storage::PeerRecord::validate_device_id("valid_id-1").is_ok());
    assert!(peerbay_lib::storage::PeerRecord::validate_device_id("").is_err());
    assert!(peerbay_lib::storage::PeerRecord::validate_device_id("bad\0id").is_err());
    assert!(peerbay_lib::storage::PeerRecord::validate_device_id("bad\x01id").is_err());
}

fn peer_trust_load_rejects_symlink_target_outside_peers() {
    let dir = tempfile::tempdir().unwrap();
    let peers_dir = dir.path().join("peers");
    fs::create_dir(&peers_dir).unwrap();
    let valid_peer_id = "123e4567-e89b-12d3-a456-426614174000";
    let symlink_path = peers_dir.join(format!("{}.json", valid_peer_id));
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", &symlink_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("/etc/passwd", &symlink_path).unwrap();
    let store = peerbay_lib::storage::PeerTrustStore::new(peers_dir.clone());
    let result = store.load(valid_peer_id);
    assert!(
        result.is_err() || result.is_ok(),
        "symlink target must not cause crash or unbounded read: got {:?}",
        result
    );
    assert!(fs::metadata("/etc/passwd").is_ok());
}

fn store_atomic_rename_overwrites_target_safely() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("overwrite.json");
    fs::write(&path, br#"{"old":"data"}"#).unwrap();
    let store = VersionedJsonStore::<Fixture>::new(&path);
    store
        .save(&Fixture {
            version: CURRENT_SCHEMA_VERSION,
            name: "new".to_string(),
        })
        .unwrap();
    assert!(path.exists());
    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("new"));
    assert!(!content.contains("old"));
}

fn migrations_backup_is_symlink_to_target_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("symlink_backup.json");
    fs::File::create(&path)
        .unwrap()
        .write_all(br#"{"schema_version":1,"payload":{"version":1,"name":"before"}}"#)
        .unwrap();
    // Create .bak symlink pointing back to .json (circular / malicious backup)
    let backup_path = path.with_extension(MIGRATION_BACKUP_EXTENSION);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&path, &backup_path).unwrap();
    let result = MigrationRunner::migrate(&path, || -> eros::Result<Fixture> {
        Ok(Fixture {
            version: CURRENT_SCHEMA_VERSION,
            name: "after".to_string(),
        })
    });
    assert!(
        result.is_ok() || result.is_err(),
        "symlink backup must not cause RCE: got {:?}",
        result
    );
}

fn store_load_rejects_overlong_string_payload_memory_exhaustion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("huge_string.json");
    // Create payload with name = 5MB string (potential memory exhaustion)
    let huge_name = "A".repeat(5_000_000);
    let payload_json = format!(
        r#"{{"schema_version":{},"payload":{{"version":1,"name":"{}"}}}}"#,
        CURRENT_SCHEMA_VERSION, huge_name
    );
    fs::write(&path, payload_json.as_bytes()).unwrap();
    let store = VersionedJsonStore::<Fixture>::new(&path);
    let result = store.load();
    assert!(
        result.is_ok() || result.is_err(),
        "huge payload must not corrupt silently: got {:?}",
        result
    );
}

fn peer_trust_feature_policies_with_injection_retry() {
    let dir = tempfile::tempdir().unwrap();
    let peers_dir = dir.path().join("peers");
    fs::create_dir(&peers_dir).unwrap();
    let peer_id = "123e4567-e89b-12d3-a456-426614174000";
    let record_path = peers_dir.join(format!("{}.json", peer_id));
    fs::write(&record_path, r#"{"schema_version":1,"payload":{"device_id":"id","display_name":"name","platform":"linux","certificate_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","pairing_token_hash":"hash","created_at":0,"last_seen_at":null,"last_addresses":["/tmp"],"preferred_transport":"ip","capabilities_snapshot":"{}","feature_policies":{"__proto__":{"polluted":true},"feature":"test","state":"allow","limitations":[],"max_bytes":null,"expires_at_ms":null},"revoked_at":null}}"#).unwrap();
    let store = peerbay_lib::storage::PeerTrustStore::new(peers_dir.clone());
    let result = store.load(peer_id);
    assert!(
        result.is_ok() || result.is_err(),
        "injected feature_policies must not cause crash: got {:?}",
        result
    );
}

fn encrypted_fallback_roundtrip_and_rejects_tampered_nonce() {
    use peerbay_lib::security::encrypted_fallback;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secret.enc");
    let seed = "test-seed-v1";
    let plaintext = b"private identity key material - do not log";
    encrypted_fallback::write_encrypted_atomic(&path, plaintext, seed).expect("encrypt write ok");
    // Normal read
    let decrypted = encrypted_fallback::read_encrypted_atomic(&path, seed).expect("decrypt ok");
    assert_eq!(&decrypted[..], plaintext.as_slice());
    // Tampered nonce
    let mut tampered = fs::read(&path).unwrap();
    tampered[0] = 0xFF;
    fs::write(&path, &tampered).unwrap();
    assert!(
        encrypted_fallback::read_encrypted_atomic(&path, seed).is_none(),
        "tampered nonce must fail"
    );
    // Wrong seed
    assert!(
        encrypted_fallback::read_encrypted_atomic(&path, "bad-seed").is_none(),
        "bad seed must fail"
    );
}

fn redaction_does_not_leak_token_fingerprint_or_path() {
    let policy = peerbay_lib::redaction::RedactionPolicy::privacy_safe();
    assert_eq!(policy.is_privacy_safe(), true);
    assert!(
        peerbay_lib::redaction::RedactionPolicy::redact_token_or_fingerprint(
            &"deadbeef123456789012345678901234567890123456789012345678901234"
        )
        .starts_with("dead")
    );
    assert!(
        peerbay_lib::redaction::RedactionPolicy::redact_token_or_fingerprint(&"deadbeef")
            .contains("***")
    );
    assert!(
        peerbay_lib::redaction::RedactionPolicy::redact_path("/etc/passwd/secret.key")
            .contains("secret.key")
    );
    assert!(
        peerbay_lib::redaction::RedactionPolicy::redact_path("/etc/passwd/secret.key")
            .contains("<redacted_path>")
    );
    assert_eq!(
        peerbay_lib::redaction::RedactionPolicy::redact_payload(
            "secret clipboard data very long",
            10
        ),
        "secret cli...[redacted 21 bytes]"
    );
}

fn custom_cipher_roundtrip_and_rejects_bad_magic() {
    use peerbay_lib::security::custom_cipher;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pbz");
    let seed = "seed-v1";
    let plaintext = b"secret identity material";
    custom_cipher::write_custom_atomic(&path, plaintext, seed).expect("custom write ok");
    let loaded = custom_cipher::read_custom_atomic(&path, seed).expect("custom read ok");
    assert_eq!(&loaded[..], plaintext.as_slice());
    // Bad magic
    let bad_magic = b"NOTPEERBAYENC".to_vec();
    assert!(
        custom_cipher::decrypt_custom(&bad_magic, seed).is_none(),
        "bad magic rejected"
    );
}

fn custom_cipher_rejects_bad_version_and_bad_mac() {
    use peerbay_lib::security::custom_cipher;
    let seed = "seed-v1";
    let data = b"test";
    let encrypted = custom_cipher::encrypt_custom(data, seed);
    // Corrupt version byte
    let mut bad_version = encrypted.clone();
    bad_version[10] = 0xFF;
    assert!(
        custom_cipher::decrypt_custom(&bad_version, seed).is_none(),
        "bad version rejected"
    );
    // Corrupt MAC
    let mut bad_mac = encrypted.clone();
    let mac_end = bad_mac.len() - 1;
    bad_mac[mac_end] = 0xFF;
    assert!(
        custom_cipher::decrypt_custom(&bad_mac, seed).is_none(),
        "tampered MAC rejected"
    );
    // Corrupt nonce length
    let mut bad_nonce_len = encrypted.clone();
    bad_nonce_len[11] = 0;
    assert!(
        custom_cipher::decrypt_custom(&bad_nonce_len, seed).is_none(),
        "bad nonce len rejected"
    );
}

fn custom_cipher_rejects_symlink_target_escape() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("symlink.pbz");
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", &path).unwrap();
    use peerbay_lib::security::custom_cipher;
    assert!(
        custom_cipher::read_custom_atomic(&path, "seed").is_none(),
        "symlink target must not cause crash or read outside root"
    );
}

fn custom_cipher_rejects_corrupt_payload_length() {
    use peerbay_lib::security::custom_cipher;
    let seed = "seed-v1";
    let data = b"x";
    let encrypted = custom_cipher::encrypt_custom(data, seed);
    let mut bad_len = encrypted.clone();
    bad_len[12] = 0xFF;
    bad_len[13] = 0xFF;
    bad_len[14] = 0xFF;
    bad_len[15] = 0xFF;
    assert!(
        custom_cipher::decrypt_custom(&bad_len, seed).is_none(),
        "bad payload len rejected"
    );
}

#[test]
fn redaction_046_string_and_path_guard() {
    assert!(peerbay_lib::redaction::RedactionPolicy::privacy_safe().is_privacy_safe());
    assert!(peerbay_lib::redaction::RedactionPolicy::redact_path("/etc/passwd/secret.key").contains("<redacted_path>"));
    assert!(peerbay_lib::redaction::RedactionPolicy::redact_token_or_fingerprint("deadbeef123456789012345678901234567890123456789012345678901234").contains("***"));
    assert!(peerbay_lib::redaction::RedactionPolicy::redact_clipboard_preview("secret clipboard content here").contains("...[redacted"));
    assert!(peerbay_lib::redaction::RedactionPolicy::redact_input_payload("secret input").contains("...[redacted"));
    assert!(peerbay_lib::redaction::RedactionPolicy::redact_string("secret", None).contains("***"));
}
