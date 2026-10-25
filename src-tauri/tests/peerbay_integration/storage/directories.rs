use std::fs;
use std::path::PathBuf;

use peerbay_lib::storage::{PlatformDataDirs, StorageDirectoryError};
use uuid::Uuid;

const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

struct TestRoots {
    root: PathBuf,
    data: PathBuf,
    config: PathBuf,
    cache: PathBuf,
    log: PathBuf,
}

impl TestRoots {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "peerbay-storage-{label}-{}",
            Uuid::new_v4().simple()
        ));
        Self {
            data: root.join("data"),
            config: root.join("config"),
            cache: root.join("cache"),
            log: root.join("log"),
            root,
        }
    }

    fn dirs(&self) -> PlatformDataDirs {
        PlatformDataDirs::from_platform_roots(&self.data, &self.config, &self.cache, &self.log)
            .expect("test platform roots should be valid")
    }
}

impl Drop for TestRoots {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn directory_error(result: eros::Result<()>) -> StorageDirectoryError {
    result
        .expect_err("storage operation should fail")
        .downcast_inner::<StorageDirectoryError>()
        .expect("storage error should be preserved")
}

#[test]
fn platform_roots_are_not_created_until_layout_is_explicitly_ensured() {
    let roots = TestRoots::new("lazy");
    let dirs = roots.dirs();

    assert!(!roots.root.exists());
    assert_eq!(dirs.data_root(), roots.data);
    assert_eq!(dirs.config_root(), roots.config);
    assert_eq!(dirs.cache_root(), roots.cache);
    assert_eq!(dirs.log_root(), roots.log);
}

#[test]
fn layout_creates_only_the_backend_owned_directory_tree_and_is_idempotent() {
    let roots = TestRoots::new("layout");
    let dirs = roots.dirs();

    dirs.ensure_layout().expect("layout should be created");
    dirs.ensure_layout().expect("layout should be idempotent");

    for path in [
        dirs.data_root(),
        dirs.config_root(),
        dirs.cache_root(),
        dirs.log_root(),
        dirs.identity_dir(),
        dirs.peers_dir(),
        dirs.diagnostics_dir(),
        dirs.thumbnails_dir(),
    ] {
        assert!(path.is_dir(), "expected directory to exist: {path:?}");
    }
    for path in [
        dirs.device_id_path(),
        dirs.private_key_path(),
        dirs.certificate_path(),
        dirs.settings_path(),
        dirs.policies_path(),
        dirs.clipboard_history_path(),
    ] {
        assert!(
            !path.exists(),
            "path should not be created by layout: {path:?}"
        );
    }
}

#[test]
fn known_storage_paths_match_the_documented_data_contract() {
    let roots = TestRoots::new("contract");
    let dirs = roots.dirs();

    assert_eq!(dirs.identity_dir(), roots.data.join("identity"));
    assert_eq!(dirs.peers_dir(), roots.data.join("peers"));
    assert_eq!(dirs.diagnostics_dir(), roots.data.join("diagnostics"));
    assert_eq!(dirs.thumbnails_dir(), roots.cache.join("thumbnails"));
    assert_eq!(dirs.device_id_path(), roots.data.join("identity/device_id"));
    assert_eq!(
        dirs.private_key_path(),
        roots.data.join("identity/private_key")
    );
    assert_eq!(
        dirs.certificate_path(),
        roots.data.join("identity/certificate")
    );
    assert_eq!(dirs.settings_path(), roots.data.join("settings.json"));
    assert_eq!(dirs.policies_path(), roots.data.join("policies.json"));
    assert_eq!(
        dirs.clipboard_history_path(),
        roots.data.join("clipboard-history.db")
    );
    assert_eq!(
        dirs.peer_record_path(DEVICE_ID)
            .expect("peer ID should be valid"),
        roots
            .data
            .join("peers/123e4567-e89b-12d3-a456-426614174000.json")
    );
}

#[test]
fn peer_record_paths_accept_only_canonical_non_nil_uuid_names() {
    let roots = TestRoots::new("peer-id");
    let dirs = roots.dirs();

    assert!(dirs.peer_record_path(DEVICE_ID).is_ok());
    for peer_id in [
        "",
        " ",
        "123E4567-E89B-12D3-A456-426614174000",
        "00000000-0000-0000-0000-000000000000",
        "../../outside",
        "$(touch /tmp/peerbay-storage-rce).json",
        "123e4567-e89b-12d3-a456-426614174000/../../outside",
        "123e4567-e89b-12d3-a456-426614174000\nwhoami",
    ] {
        assert!(
            dirs.peer_record_path(peer_id).is_err(),
            "malicious peer ID unexpectedly accepted: {peer_id:?}"
        );
    }
}

#[test]
fn roots_reject_relative_empty_and_parent_traversal_paths() {
    let absolute = PathBuf::from("/tmp/peerbay-valid-root");
    let cases = [
        (
            PathBuf::new(),
            StorageDirectoryError::EmptyRoot { kind: "data" },
        ),
        (
            PathBuf::from("relative/root"),
            StorageDirectoryError::RelativeRoot { kind: "data" },
        ),
        (
            PathBuf::from("/tmp/peerbay/../escape"),
            StorageDirectoryError::ParentTraversal { kind: "data" },
        ),
    ];

    for (data_root, expected) in cases {
        let error = dirs_error(PlatformDataDirs::from_platform_roots(
            data_root,
            absolute.clone(),
            absolute.clone(),
            absolute.clone(),
        ));
        assert_eq!(error, expected);
    }
}

#[test]
fn all_derived_paths_remain_under_their_declared_root() {
    let roots = TestRoots::new("containment");
    let dirs = roots.dirs();
    let peer_path = dirs
        .peer_record_path(DEVICE_ID)
        .expect("peer ID should be valid");

    assert!(dirs.identity_dir().starts_with(dirs.data_root()));
    assert!(dirs.peers_dir().starts_with(dirs.data_root()));
    assert!(dirs.diagnostics_dir().starts_with(dirs.data_root()));
    assert!(dirs.thumbnails_dir().starts_with(dirs.cache_root()));
    assert!(dirs.device_id_path().starts_with(dirs.identity_dir()));
    assert!(dirs.private_key_path().starts_with(dirs.identity_dir()));
    assert!(dirs.certificate_path().starts_with(dirs.identity_dir()));
    assert!(dirs.settings_path().starts_with(dirs.data_root()));
    assert!(dirs.policies_path().starts_with(dirs.data_root()));
    assert!(dirs.clipboard_history_path().starts_with(dirs.data_root()));
    assert!(peer_path.starts_with(dirs.peers_dir()));
}

#[test]
fn shell_metacharacters_in_a_platform_root_remain_literal_data() {
    let roots = TestRoots::new("shell");
    let canary = roots.root.join("canary");
    let literal_root = roots.root.join("literal-$(touch canary)-`id`");
    let dirs = PlatformDataDirs::from_platform_roots(
        literal_root.join("data"),
        literal_root.join("config"),
        literal_root.join("cache"),
        literal_root.join("log"),
    )
    .expect("shell punctuation should remain literal path data");

    dirs.ensure_layout()
        .expect("literal path layout should work");
    assert!(!canary.exists());
    assert!(literal_root.join("data/identity").is_dir());
}

#[test]
fn debug_output_redacts_all_platform_paths() {
    let roots = TestRoots::new("debug-redaction");
    let dirs = roots.dirs();
    let debug = format!("{dirs:?}");

    assert!(debug.contains("<path redacted>"));
    assert!(!debug.contains(roots.root.to_string_lossy().as_ref()));
    assert!(!debug.contains("private_key"));
    assert!(!debug.contains("certificate"));
}

#[test]
fn ensure_layout_rejects_file_collisions_without_overwriting_them() {
    let roots = TestRoots::new("file-collision");
    fs::create_dir_all(&roots.root).expect("test root should be creatable");
    fs::write(&roots.data, b"not a directory").expect("collision file should be creatable");
    let dirs = roots.dirs();

    assert_eq!(
        directory_error(dirs.ensure_layout()),
        StorageDirectoryError::PathIsNotDirectory { kind: "data" }
    );
    assert_eq!(
        fs::read(&roots.data).expect("collision file should survive"),
        b"not a directory"
    );
}

#[cfg(unix)]
#[test]
fn ensure_layout_rejects_symlinked_roots_without_following_them() {
    use std::os::unix::fs::symlink;

    let roots = TestRoots::new("symlink");
    let outside = roots.root.join("outside");
    let data_link = roots.root.join("data");
    fs::create_dir_all(&outside).expect("outside directory should be creatable");
    symlink(&outside, &data_link).expect("data symlink should be creatable");
    let dirs = roots.dirs();

    assert_eq!(
        directory_error(dirs.ensure_layout()),
        StorageDirectoryError::PathIsSymlink { kind: "data" }
    );
    assert!(!outside.join("identity").exists());
}

#[cfg(unix)]
#[test]
fn ensure_layout_rejects_symlinked_parent_components_without_following_them() {
    use std::os::unix::fs::symlink;

    let roots = TestRoots::new("symlink-parent");
    let outside = roots.root.join("outside");
    let redirected_parent = roots.root.join("redirected-parent");
    fs::create_dir_all(&outside).expect("outside directory should be creatable");
    symlink(&outside, &redirected_parent).expect("parent symlink should be creatable");
    let dirs = PlatformDataDirs::from_platform_roots(
        redirected_parent.join("data"),
        roots.config.clone(),
        roots.cache.clone(),
        roots.log.clone(),
    )
    .expect("symlinked parent is not inspected until layout creation");

    assert_eq!(
        directory_error(dirs.ensure_layout()),
        StorageDirectoryError::PathIsSymlink { kind: "data" }
    );
    assert!(!outside.join("data").exists());
}

#[test]
fn storage_errors_do_not_echo_untrusted_paths_or_commands() {
    let payload = "/tmp/secret-$(touch /tmp/pwned);../../private";
    let error =
        PlatformDataDirs::from_platform_roots(payload, "/tmp/config", "/tmp/cache", "/tmp/log")
            .expect_err("relative untrusted path should fail");
    let message = error.to_string();

    assert!(!message.contains(payload));
    assert!(!message.contains("touch"));
    assert!(!message.contains("/tmp/secret"));
}

fn dirs_error(result: eros::Result<PlatformDataDirs>) -> StorageDirectoryError {
    result
        .expect_err("platform roots should be rejected")
        .downcast_inner::<StorageDirectoryError>()
        .expect("storage error should be preserved")
}
