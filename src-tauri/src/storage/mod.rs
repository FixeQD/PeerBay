//! Persistent-storage boundary.

mod directories;
mod errors;

pub mod store;

pub use directories::PlatformDataDirs;
pub use errors::{StorageDirectoryError, StorageError};
pub use store::{VersionedJsonStore, CURRENT_SCHEMA_VERSION};
