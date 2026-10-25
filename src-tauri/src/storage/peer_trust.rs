use std::fs;

use path_clean::PathClean;

use super::errors::StorageError;
use super::store::VersionedJsonStore;

/// A trust record for a paired peer device.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub struct PeerRecord {
    pub device_id: String,
    pub display_name: String,
    pub platform: String,
    pub certificate_fingerprint: String,
    pub pairing_token_hash: String,
    pub created_at: u64,
    pub last_seen_at: Option<u64>,
    pub last_addresses: Vec<String>,
    pub preferred_transport: String,
    pub capabilities_snapshot: String,
    pub feature_policies: serde_json::Value,
    pub revoked_at: Option<u64>,
}

impl PeerRecord {
    pub fn new(
        device_id: impl Into<String>,
        display_name: impl Into<String>,
        platform: impl Into<String>,
        fingerprint: impl Into<String>,
        token_hash: impl Into<String>,
        preferred_transport: impl Into<String>,
    ) -> Self {
        Self {
            device_id: device_id.into(),
            display_name: display_name.into(),
            platform: platform.into(),
            certificate_fingerprint: fingerprint.into(),
            pairing_token_hash: token_hash.into(),
            created_at: 0,
            last_seen_at: None,
            last_addresses: Vec::new(),
            preferred_transport: preferred_transport.into(),
            capabilities_snapshot: String::new(),
            feature_policies: serde_json::Value::Null,
            revoked_at: None,
        }
    }

    pub fn validate_fingerprint(fingerprint: &str) -> eros::Result<()> {
        if fingerprint.len() != 64 {
            return Err(eros::error!(StorageError::ValidationFailed {
                reason: "fingerprint length must be 64"
            }));
        }
        if !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(eros::error!(StorageError::ValidationFailed {
                reason: "fingerprint must be hex"
            }));
        }
        Ok(())
    }

    pub fn validate_device_id(id: &str) -> eros::Result<()> {
        if id.trim().is_empty() {
            return Err(eros::error!(StorageError::ValidationFailed {
                reason: "device_id empty"
            }));
        }
        if id.chars().any(|c| c.is_control()) {
            return Err(eros::error!(StorageError::ValidationFailed {
                reason: "device_id contains control char"
            }));
        }
        Ok(())
    }

    pub fn validate_addresses(addresses: &[String]) -> eros::Result<()> {
        for addr in addresses {
            if addr.contains('\0') {
                return Err(eros::error!(StorageError::ValidationFailed {
                    reason: "address null byte"
                }));
            }
            if addr.chars().any(|c| c.is_control()) {
                return Err(eros::error!(StorageError::ValidationFailed {
                    reason: "address control character"
                }));
            }
            let path = std::path::Path::new(addr);
            if !path.is_absolute() {
                return Err(eros::error!(StorageError::ValidationFailed {
                    reason: "address not absolute"
                }));
            }
            let cleaned = path.clean();
            if cleaned.as_os_str().is_empty()
                || cleaned
                    .components()
                    .next()
                    .is_some_and(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(eros::error!(StorageError::ValidationFailed {
                    reason: "address traversal after clean"
                }));
            }
            if cleaned.as_os_str() != path.as_os_str() {
                let cleaned_str = cleaned.to_string_lossy();
                if cleaned_str.contains("/../")
                    || cleaned_str.ends_with("/..")
                    || cleaned_str.contains("/./")
                    || cleaned_str.ends_with("/.")
                {
                    return Err(eros::error!(StorageError::ValidationFailed {
                        reason: "address traversal after clean"
                    }));
                }
            }
        }
        Ok(())
    }

    pub fn revoke(&mut self, at_ms: u64) {
        self.revoked_at = Some(at_ms);
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Persistent storage manager for peer trust records.
pub struct PeerTrustStore {
    peers_dir: std::path::PathBuf,
}

impl PeerTrustStore {
    pub fn new(peers_dir: std::path::PathBuf) -> Self {
        Self { peers_dir }
    }

    pub fn load(&self, peer_id: &str) -> eros::Result<PeerRecord> {
        let record_path = self.resolve_path(peer_id)?;
        let store: VersionedJsonStore<PeerRecord> = VersionedJsonStore::new(record_path);
        let record = store.load()?;
        PeerRecord::validate_fingerprint(&record.certificate_fingerprint)?;
        if !record.device_id.is_empty() {
            PeerRecord::validate_device_id(&record.device_id)?;
        }
        PeerRecord::validate_addresses(&record.last_addresses)?;
        Ok(record)
    }

    pub fn save(&self, peer_id: &str, record: &PeerRecord) -> eros::Result<()> {
        PeerRecord::validate_fingerprint(&record.certificate_fingerprint)?;
        PeerRecord::validate_device_id(&record.device_id)?;
        PeerRecord::validate_addresses(&record.last_addresses)?;
        let record_path = self.resolve_path(peer_id)?;
        let store: VersionedJsonStore<PeerRecord> = VersionedJsonStore::new(record_path);
        store.save(record)?;
        Ok(())
    }

    pub fn remove(&self, peer_id: &str) -> eros::Result<bool> {
        let record_path = self.resolve_path(peer_id)?;
        if record_path.exists() {
            fs::remove_file(&record_path).map_err(|_| {
                eros::error!(StorageError::AtomicWriteFailed).context("remove peer record")
            })?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn revoke(&self, peer_id: &str, at_ms: u64) -> eros::Result<()> {
        let mut record = self.load(peer_id)?;
        record.revoke(at_ms);
        self.save(peer_id, &record)?;
        Ok(())
    }

    pub fn list_active(&self) -> eros::Result<Vec<String>> {
        let mut peers = Vec::new();
        for entry in fs::read_dir(&self.peers_dir)
            .map_err(|_| eros::error!(StorageError::AtomicReadFailed).context("read peers dir"))?
        {
            let entry = entry.map_err(|_| {
                eros::error!(StorageError::AtomicReadFailed).context("read peers entry")
            })?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with(".json") {
                let peer_id = name_str.trim_end_matches(".json").to_string();
                if let Ok(record) = self.load(&peer_id)
                    && !record.is_revoked() {
                        peers.push(peer_id);
                    }
            }
        }
        Ok(peers)
    }

    /// Resolve the file path for a given peer UUID.
    fn resolve_path(&self, peer_id: &str) -> eros::Result<std::path::PathBuf> {
        let parsed =
            uuid::Uuid::parse_str(peer_id).map_err(|_| StorageError::ValidationFailed {
                reason: "invalid peer id for record",
            })?;
        if parsed.is_nil() || parsed.to_string() != peer_id {
            return Err(eros::error!(StorageError::ValidationFailed {
                reason: "invalid or nil peer id"
            })
            .context("invalid or nil peer id"));
        }
        Ok(self.peers_dir.join(format!("{peer_id}.json")))
    }
}
