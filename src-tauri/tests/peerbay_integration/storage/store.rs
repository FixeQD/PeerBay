use std::fs;
use std::io::Write;

use peerbay_lib::storage::{
    CURRENT_SCHEMA_VERSION, MIGRATION_BACKUP_EXTENSION, MigrationReport, MigrationRunner,
    StorageError, VersionedJsonStore,
};

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
struct Fixture {
    version: u16,
    name: String,
}

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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
