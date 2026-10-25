use std::fmt::{Debug, Formatter};
use std::fs;
use std::path::{Component, Path, PathBuf};

use tauri::{AppHandle, Manager, Runtime};
use uuid::Uuid;

use super::errors::StorageDirectoryError;

const IDENTITY_DIR: &str = "identity";
const PEERS_DIR: &str = "peers";
const DIAGNOSTICS_DIR: &str = "diagnostics";
const THUMBNAILS_DIR: &str = "thumbnails";
const DEVICE_ID_FILE: &str = "device_id";
const PRIVATE_KEY_FILE: &str = "private_key";
const CERTIFICATE_FILE: &str = "certificate";
const SETTINGS_FILE: &str = "settings.json";
const POLICIES_FILE: &str = "policies.json";
const CLIPBOARD_HISTORY_FILE: &str = "clipboard-history.db";
const PEER_RECORD_EXTENSION: &str = "json";

#[derive(Clone, PartialEq, Eq)]
pub struct PlatformDataDirs {
    data_root: PathBuf,
    config_root: PathBuf,
    cache_root: PathBuf,
    log_root: PathBuf,
    identity_dir: PathBuf,
    peers_dir: PathBuf,
    diagnostics_dir: PathBuf,
    thumbnails_dir: PathBuf,
}

impl PlatformDataDirs {
    pub fn from_tauri<R: Runtime>(app: &AppHandle<R>) -> eros::Result<Self> {
        let resolver = app.path();
        let data_root = resolver.app_local_data_dir().map_err(|_| {
            eros::error!(StorageDirectoryError::PlatformPathUnavailable { kind: "data" })
        })?;
        let config_root = resolver.app_config_dir().map_err(|_| {
            eros::error!(StorageDirectoryError::PlatformPathUnavailable { kind: "config" })
        })?;
        let cache_root = resolver.app_cache_dir().map_err(|_| {
            eros::error!(StorageDirectoryError::PlatformPathUnavailable { kind: "cache" })
        })?;
        let log_root = resolver.app_log_dir().map_err(|_| {
            eros::error!(StorageDirectoryError::PlatformPathUnavailable { kind: "log" })
        })?;

        Self::from_platform_roots(data_root, config_root, cache_root, log_root)
    }

    pub fn from_platform_roots(
        data_root: impl Into<PathBuf>,
        config_root: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
        log_root: impl Into<PathBuf>,
    ) -> eros::Result<Self> {
        let data_root = validate_root("data", data_root.into())?;
        let config_root = validate_root("config", config_root.into())?;
        let cache_root = validate_root("cache", cache_root.into())?;
        let log_root = validate_root("log", log_root.into())?;

        let identity_dir = data_root.join(IDENTITY_DIR);
        let peers_dir = data_root.join(PEERS_DIR);
        let diagnostics_dir = data_root.join(DIAGNOSTICS_DIR);
        let thumbnails_dir = cache_root.join(THUMBNAILS_DIR);

        for (kind, path) in [
            ("identity", &identity_dir),
            ("peers", &peers_dir),
            ("diagnostics", &diagnostics_dir),
            ("thumbnails", &thumbnails_dir),
        ] {
            ensure_child_path(kind, path)?;
        }

        Ok(Self {
            data_root,
            config_root,
            cache_root,
            log_root,
            identity_dir,
            peers_dir,
            diagnostics_dir,
            thumbnails_dir,
        })
    }

    pub fn ensure_layout(&self) -> eros::Result<()> {
        for (kind, path) in [
            ("data", &self.data_root),
            ("config", &self.config_root),
            ("cache", &self.cache_root),
            ("log", &self.log_root),
            ("identity", &self.identity_dir),
            ("peers", &self.peers_dir),
            ("diagnostics", &self.diagnostics_dir),
            ("thumbnails", &self.thumbnails_dir),
        ] {
            ensure_directory(kind, path)?;
        }

        Ok(())
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub fn config_root(&self) -> &Path {
        &self.config_root
    }

    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    pub fn log_root(&self) -> &Path {
        &self.log_root
    }

    pub fn identity_dir(&self) -> &Path {
        &self.identity_dir
    }

    pub fn peers_dir(&self) -> &Path {
        &self.peers_dir
    }

    pub fn diagnostics_dir(&self) -> &Path {
        &self.diagnostics_dir
    }

    pub fn thumbnails_dir(&self) -> &Path {
        &self.thumbnails_dir
    }

    pub fn device_id_path(&self) -> PathBuf {
        self.identity_dir.join(DEVICE_ID_FILE)
    }

    pub fn private_key_path(&self) -> PathBuf {
        self.identity_dir.join(PRIVATE_KEY_FILE)
    }

    pub fn certificate_path(&self) -> PathBuf {
        self.identity_dir.join(CERTIFICATE_FILE)
    }

    pub fn settings_path(&self) -> PathBuf {
        self.data_root.join(SETTINGS_FILE)
    }

    pub fn policies_path(&self) -> PathBuf {
        self.data_root.join(POLICIES_FILE)
    }

    pub fn clipboard_history_path(&self) -> PathBuf {
        self.data_root.join(CLIPBOARD_HISTORY_FILE)
    }

    pub fn peer_record_path(&self, peer_id: &str) -> eros::Result<PathBuf> {
        let parsed = Uuid::parse_str(peer_id)
            .map_err(|_| eros::error!(StorageDirectoryError::InvalidPeerId))?;
        if parsed.is_nil() || parsed.to_string() != peer_id {
            return Err(eros::error!(StorageDirectoryError::InvalidPeerId));
        }

        Ok(self
            .peers_dir
            .join(format!("{peer_id}.{PEER_RECORD_EXTENSION}")))
    }
}

impl Debug for PlatformDataDirs {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlatformDataDirs")
            .field("data_root", &"<path redacted>")
            .field("config_root", &"<path redacted>")
            .field("cache_root", &"<path redacted>")
            .field("log_root", &"<path redacted>")
            .field("identity_dir", &"<path redacted>")
            .field("peers_dir", &"<path redacted>")
            .field("diagnostics_dir", &"<path redacted>")
            .field("thumbnails_dir", &"<path redacted>")
            .finish()
    }
}

fn validate_root(kind: &'static str, path: PathBuf) -> eros::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(eros::error!(StorageDirectoryError::EmptyRoot { kind }));
    }
    if !path.is_absolute() {
        return Err(eros::error!(StorageDirectoryError::RelativeRoot { kind }));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(eros::error!(StorageDirectoryError::ParentTraversal {
            kind
        }));
    }

    Ok(path)
}

fn ensure_child_path(kind: &'static str, path: &Path) -> eros::Result<()> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(eros::error!(StorageDirectoryError::ParentTraversal {
            kind
        }));
    }

    Ok(())
}

fn ensure_directory(kind: &'static str, path: &Path) -> eros::Result<()> {
    reject_symlink_components(kind, path)?;

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(eros::error!(StorageDirectoryError::PathIsSymlink { kind }))
        }
        Ok(metadata) if !metadata.is_dir() => {
            Err(eros::error!(StorageDirectoryError::PathIsNotDirectory {
                kind
            }))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|_| eros::error!(StorageDirectoryError::CreateDirectoryFailed { kind }))?;
            reject_symlink_components(kind, path)?;
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    Err(eros::error!(StorageDirectoryError::PathIsSymlink { kind }))
                }
                Ok(metadata) if !metadata.is_dir() => {
                    Err(eros::error!(StorageDirectoryError::PathIsNotDirectory {
                        kind
                    }))
                }
                Ok(_) => Ok(()),
                Err(_) => Err(eros::error!(StorageDirectoryError::CreateDirectoryFailed {
                    kind
                })),
            }
        }
        Err(_) => Err(eros::error!(StorageDirectoryError::CreateDirectoryFailed {
            kind
        })),
    }
}

fn reject_symlink_components(kind: &'static str, path: &Path) -> eros::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(eros::error!(StorageDirectoryError::PathIsSymlink { kind }));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                return Err(eros::error!(StorageDirectoryError::CreateDirectoryFailed {
                    kind
                }));
            }
        }
    }

    Ok(())
}
