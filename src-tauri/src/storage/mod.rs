//! Persistent-storage boundary.

mod directories;
mod errors;

pub use directories::PlatformDataDirs;
pub use errors::StorageDirectoryError;
