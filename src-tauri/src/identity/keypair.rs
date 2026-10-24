use std::fmt::{Debug, Formatter};

use ed25519_dalek::SigningKey;
use rand::rng;
use zeroize::{Zeroize, Zeroizing};

use super::errors::IdentityKeyPairError;
use super::{IDENTITY_PRIVATE_KEY_LENGTH, IDENTITY_PUBLIC_KEY_LENGTH};

pub struct IdentityKeyPair {
    private_key: Zeroizing<[u8; IDENTITY_PRIVATE_KEY_LENGTH]>,
    public_key: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rng());
        Self::from_private_bytes(signing_key.to_bytes())
    }

    pub fn from_private_bytes(private_key: [u8; IDENTITY_PRIVATE_KEY_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key);
        let public_key = signing_key.verifying_key().to_bytes();

        Self {
            private_key: Zeroizing::new(private_key),
            public_key,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; IDENTITY_PUBLIC_KEY_LENGTH] {
        self.public_key
    }

    pub fn with_private_key<R>(
        &self,
        callback: impl FnOnce(&[u8; IDENTITY_PRIVATE_KEY_LENGTH]) -> R,
    ) -> R {
        callback(&self.private_key)
    }

    pub fn private_key_bytes(&self) -> PrivateKeyBytes {
        PrivateKeyBytes(self.private_key.clone())
    }

    pub fn validate(&self) -> eros::Result<()> {
        let signing_key = SigningKey::from_bytes(&self.private_key);
        if signing_key.verifying_key().to_bytes() != self.public_key {
            return Err(eros::error!(IdentityKeyPairError::PublicKeyMismatch));
        }

        Ok(())
    }
}

impl Debug for IdentityKeyPair {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityKeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &"<redacted>")
            .finish()
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        self.public_key.zeroize();
    }
}

pub struct PrivateKeyBytes(Zeroizing<[u8; IDENTITY_PRIVATE_KEY_LENGTH]>);

impl PrivateKeyBytes {
    pub fn as_bytes(&self) -> &[u8; IDENTITY_PRIVATE_KEY_LENGTH] {
        &self.0
    }
}

impl Debug for PrivateKeyBytes {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateKeyBytes(<redacted>)")
    }
}

impl Drop for PrivateKeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
