//! Persistent-storage boundary.

mod directories;
mod errors;

pub mod migrations;
pub mod peer_trust;
pub mod store;

pub use directories::PlatformDataDirs;
pub use errors::{StorageDirectoryError, StorageError};
pub use migrations::{MIGRATION_BACKUP_EXTENSION, MigrationReport, MigrationRunner};
pub use peer_trust::{PeerRecord, PeerTrustStore};
pub use store::{CURRENT_SCHEMA_VERSION, VersionedJsonStore};
