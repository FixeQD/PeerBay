use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use super::errors::StorageError;

pub const CURRENT_SCHEMA_VERSION: u16 = 1;

pub struct VersionedJsonStore<T> {
    path: std::path::PathBuf,
    phantom: std::marker::PhantomData<T>,
}

impl<T> VersionedJsonStore<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().into(),
            phantom: std::marker::PhantomData,
        }
    }

    pub fn load(&self) -> eros::Result<T> {
        let mut file = fs::File::open(&self.path)
            .map_err(|_| eros::error!(StorageError::AtomicReadFailed).context("open store file"))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|_| {
            eros::error!(StorageError::AtomicReadFailed).context("read store contents")
        })?;

        let raw: serde_json::Value = serde_json::from_str(&contents).map_err(|_| {
            eros::error!(StorageError::InvalidJson {
                reason: "parse error"
            })
            .context("parse versioned JSON store")
        })?;

        let version = raw
            .get("schema_version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16);
        match version {
            None => {
                return Err(eros::error!(StorageError::SchemaVersionMissing)
                    .context("missing schema_version"));
            }
            Some(v) if v != CURRENT_SCHEMA_VERSION => {
                return Err(eros::error!(StorageError::SchemaVersionMismatch {
                    expected: CURRENT_SCHEMA_VERSION,
                    found: v,
                })
                .context("store schema version mismatch"));
            }
            Some(_) => {}
        }

        let payload: T = serde_json::from_value(
            raw.get("payload")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|_| {
            eros::error!(StorageError::InvalidJson {
                reason: "payload deserialize error"
            })
            .context("deserialize store payload")
        })?;

        validate_store_payload(&payload)?;
        Ok(payload)
    }

    pub fn save(&self, payload: &T) -> eros::Result<()> {
        let tmp_path = self.path.with_extension("tmp");
        let envelope = serde_json::json!({
            "schema_version": CURRENT_SCHEMA_VERSION,
            "payload": payload,
        });
        let serialized = serde_json::to_string(&envelope).map_err(|_| {
            eros::error!(StorageError::InvalidJson {
                reason: "serialize error"
            })
            .context("serialize versioned JSON store")
        })?;

        {
            let mut tmp_file = fs::File::create(&tmp_path).map_err(|_| {
                eros::error!(StorageError::AtomicWriteFailed).context("create temporary store file")
            })?;
            tmp_file.write_all(serialized.as_bytes()).map_err(|_| {
                eros::error!(StorageError::AtomicWriteFailed).context("write temporary store file")
            })?;
            tmp_file.flush().map_err(|_| {
                eros::error!(StorageError::AtomicWriteFailed).context("flush temporary store file")
            })?;
        }

        fs::rename(&tmp_path, &self.path).map_err(|_| {
            eros::error!(StorageError::AtomicWriteFailed).context("commit atomic store rename")
        })?;
        Ok(())
    }

    pub fn read_schema_version(&self) -> eros::Result<u16> {
        if !self.path.exists() {
            return Ok(CURRENT_SCHEMA_VERSION);
        }
        let mut file = fs::File::open(&self.path).map_err(|_| {
            eros::error!(StorageError::AtomicReadFailed).context("open store for version check")
        })?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|_| {
            eros::error!(StorageError::AtomicReadFailed).context("read store for version check")
        })?;
        let raw: serde_json::Value = serde_json::from_str(&contents).map_err(|_| {
            eros::error!(StorageError::InvalidJson {
                reason: "parse error"
            })
            .context("parse versioned JSON store for version check")
        })?;
        match raw
            .get("schema_version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u16)
        {
            Some(v) => Ok(v),
            None => Err(eros::error!(StorageError::SchemaVersionMissing)
                .context("missing schema_version in version check")),
        }
    }
}

fn validate_store_payload<T>(payload: &T) -> eros::Result<()>
where
    T: serde::Serialize,
{
    let value = serde_json::to_value(payload).map_err(|_| {
        eros::error!(StorageError::ValidationFailed {
            reason: "serialize for validation"
        })
        .context("validate payload serialization")
    })?;
    if value.is_null() {
        return Err(eros::error!(StorageError::ValidationFailed {
            reason: "null payload"
        })
        .context("payload is null"));
    }
    if !value.is_object() {
        return Err(eros::error!(StorageError::ValidationFailed {
            reason: "payload must be JSON object"
        })
        .context("payload not object"));
    }
    if value.as_object().unwrap().is_empty() {
        return Err(eros::error!(StorageError::ValidationFailed {
            reason: "empty payload object"
        })
        .context("payload empty"));
    }
    Ok(())
}
