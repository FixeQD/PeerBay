//! Local device identity and identity-key boundaries.

mod device;
mod errors;
mod keypair;
mod store;
mod validation;

pub use device::DeviceIdentity;
pub use errors::{DeviceIdentityError, IdentityKeyPairError, IdentityKeyStoreError};
pub use keypair::{IdentityKeyPair, PrivateKeyBytes};
pub use store::IdentityKeyStore;
pub use validation::MAX_DEVICE_NAME_LENGTH;

pub const IDENTITY_PRIVATE_KEY_LENGTH: usize = 32;
pub const IDENTITY_PUBLIC_KEY_LENGTH: usize = 32;
