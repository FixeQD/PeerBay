//! Persistent-storage boundary.

mod directories;
mod errors;

pub mod migrations;
pub mod store;

pub use directories::PlatformDataDirs;
pub use errors::{StorageDirectoryError, StorageError};
pub use migrations::{MIGRATION_BACKUP_EXTENSION, MigrationReport, MigrationRunner};
pub use store::{CURRENT_SCHEMA_VERSION, VersionedJsonStore};
