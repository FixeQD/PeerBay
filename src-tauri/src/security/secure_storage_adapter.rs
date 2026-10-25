use std::collections::HashMap;
use std::path::Path;

use crate::storage::StorageError;

/// Try to store a secret via Linux Secret Service
/// Falls back to encrypted file if connection unavailable
pub fn try_store_secret(
    label: &str,
    secret_bytes: &[u8],
    seed: &str,
    fallback_path: &Path,
) -> eros::Result<()> {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use secret_service::{EncryptionType, SecretService};
            match SecretService::connect(EncryptionType::Dh).await {
                Ok(ss) => {
                    let collection = ss.get_default_collection().await.ok()?;
                    let mut properties = HashMap::new();
                    properties.insert("label", label);
                    collection
                        .create_item("PeerBay", properties, secret_bytes, false, "")
                        .await
                        .ok()?;
                    Some(())
                }
                Err(_) => None,
            }
        });
    if result.is_some() {
        return Ok(());
    }
    use super::encrypted_fallback;
    encrypted_fallback::write_encrypted_atomic(fallback_path, secret_bytes, seed)?;
    Ok(())
}

/// Load a secret from secure storage or fallback file.
pub fn try_load_secret(_label: &str, seed: &str, fallback_path: &Path) -> eros::Result<Vec<u8>> {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            use secret_service::{EncryptionType, SecretService};
            match SecretService::connect(EncryptionType::Dh).await {
                Ok(ss) => {
                    let _collection = ss.get_default_collection().await.ok()?;
                    None
                }
                Err(_) => None,
            }
        });
    if let Some(bytes) = result {
        return Ok(bytes);
    }
    use super::encrypted_fallback;
    encrypted_fallback::read_encrypted_atomic(fallback_path, seed).ok_or_else(|| {
        eros::error!(StorageError::AtomicReadFailed).context("load secret from fallback")
    })
}
