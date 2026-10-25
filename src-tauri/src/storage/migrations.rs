use std::fs;
use std::path::Path;

use super::errors::StorageError;
use super::store::{CURRENT_SCHEMA_VERSION, VersionedJsonStore};

pub const MIGRATION_BACKUP_EXTENSION: &str = "bak";

#[derive(Debug, PartialEq, Eq)]
pub struct MigrationReport {
    pub from_version: u16,
    pub to_version: u16,
    pub backup_path: Option<std::path::PathBuf>,
    pub rolled_back: bool,
}

pub struct MigrationRunner;

impl MigrationRunner {
    pub fn migrate<T, P>(
        store_path: P,
        migrate_fn: impl FnOnce() -> eros::Result<T>,
    ) -> eros::Result<(T, MigrationReport)>
    where
        P: AsRef<Path>,
        T: serde::de::DeserializeOwned + serde::Serialize,
    {
        let path = store_path.as_ref().to_path_buf();
        let from_version = if path.exists() {
            let temp_store: VersionedJsonStore<serde_json::Value> = VersionedJsonStore::new(&path);
            temp_store.read_schema_version().unwrap_or(0)
        } else {
            0
        };

        let backup_path = path.with_extension(MIGRATION_BACKUP_EXTENSION);
        let backup_exists = backup_path.exists();

        if !backup_exists && path.exists() {
            fs::copy(&path, &backup_path).map_err(|_| StorageError::MigrationFailed {
                reason: "backup copy failed",
            })?;
        }

        let result = migrate_fn();

        match result {
            Ok(payload) => {
                let store_after: VersionedJsonStore<serde_json::Value> =
                    VersionedJsonStore::new(&path);
                let version_after = store_after.read_schema_version()?;
                if version_after != CURRENT_SCHEMA_VERSION {
                    if backup_path.exists() {
                        fs::rename(&backup_path, &path).map_err(|_| {
                            StorageError::MigrationFailed {
                                reason: "rollback rename failed",
                            }
                        })?;
                    }
                    return Err(eros::error!(StorageError::MigrationFailed {
                        reason: "post-migration validation failed"
                    }));
                }
                let store_after: VersionedJsonStore<T> = VersionedJsonStore::new(&path);
                store_after.save(&payload)?;
                if backup_path.exists() {
                    fs::remove_file(&backup_path).ok();
                }
                Ok((
                    payload,
                    MigrationReport {
                        from_version,
                        to_version: CURRENT_SCHEMA_VERSION,
                        backup_path: Some(backup_path),
                        rolled_back: false,
                    },
                ))
            }
            Err(_) => {
                if backup_path.exists() {
                    fs::rename(&backup_path, &path).ok();
                }
                Err(eros::error!(StorageError::MigrationFailed {
                    reason: "migration function failed"
                }))
            }
        }
    }

    pub fn rollback<P: AsRef<Path>>(store_path: P, backup_path: P) -> eros::Result<()> {
        let path = store_path.as_ref().to_path_buf();
        let backup = backup_path.as_ref().to_path_buf();
        fs::rename(&backup, &path).map_err(|_| {
            eros::error!(StorageError::MigrationFailed {
                reason: "rollback rename failed"
            })
        })?;
        Ok(())
    }

    pub fn recover_previous_format<P: AsRef<Path>>(
        store_path: P,
        output_path: P,
    ) -> eros::Result<()> {
        let path = store_path.as_ref();
        let output = output_path.as_ref();
        fs::copy(path, output).map_err(|_| {
            eros::error!(StorageError::MigrationFailed {
                reason: "recovery copy failed"
            })
        })?;
        Ok(())
    }
}
