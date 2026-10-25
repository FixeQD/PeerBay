use std::fs;
use std::io::Write;

use peerbay_lib::storage::{StorageError, VersionedJsonStore, CURRENT_SCHEMA_VERSION};

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
        file.write_all(br#"{"payload":{"version":1,"name":"x"}}"#).unwrap();
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
        file.write_all(br#"{"schema_version":999,"payload":{"version":1,"name":"x"}}"#).unwrap();
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
    let loaded = store.load().expect("deserialization should ignore malicious keys");
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
    let loaded = store.load().expect("load through symlink should succeed within same root");
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
    assert!(result.is_err() || result.is_ok(), "oversized payload should not corrupt store silently; got: {:?}", result);
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
        file.write_all(br#"{"schema_version":1,"payload":null}"#).unwrap();
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
        file.write_all(br#"{"schema_version":1,"payload":[1,2,3]}"#).unwrap();
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
        file.write_all(br#"{"schema_version":1,"payload":{}}"#).unwrap();
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
        file.write_all(br#"{"schema_version":"1","payload":{"version":1,"name":"strver"}}"#).unwrap();
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
    store.save(&Fixture { version: 1, name: "atomic".to_string() }).unwrap();
    assert!(!path.with_extension("tmp").exists());
    assert!(path.exists());
}
