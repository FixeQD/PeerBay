use super::errors::IdentityKeyStoreError;
use super::keypair::IdentityKeyPair;

#[derive(Default)]
pub struct IdentityKeyStore {
    keypair: Option<IdentityKeyPair>,
}

impl IdentityKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generated() -> Self {
        let mut store = Self::new();
        store.save(IdentityKeyPair::generate());
        store
    }

    pub fn save(&mut self, keypair: IdentityKeyPair) {
        self.keypair = Some(keypair);
    }

    pub fn load(&self) -> eros::Result<&IdentityKeyPair> {
        self.keypair
            .as_ref()
            .ok_or_else(|| eros::error!(IdentityKeyStoreError::MissingKeyPair))
    }

    pub fn take(&mut self) -> Option<IdentityKeyPair> {
        self.keypair.take()
    }

    pub fn clear(&mut self) {
        self.keypair.take();
    }

    pub fn is_empty(&self) -> bool {
        self.keypair.is_none()
    }
}
