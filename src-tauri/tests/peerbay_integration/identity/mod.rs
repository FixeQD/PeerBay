mod certificate;
mod device;
mod keypair;
mod runtime;
mod security;
mod store;

use peerbay_lib::identity::{DeviceIdentityError, IdentityKeyStoreError};

const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const PRIVATE_KEY_BYTES: [u8; 32] = [7; 32];

fn identity_error(result: eros::Result<()>) -> DeviceIdentityError {
    result
        .expect_err("identity validation should fail")
        .downcast_inner::<DeviceIdentityError>()
        .expect("identity error should be preserved")
}

fn key_store_error(result: eros::Result<()>) -> IdentityKeyStoreError {
    result
        .expect_err("key store operation should fail")
        .downcast_inner::<IdentityKeyStoreError>()
        .expect("key store error should be preserved")
}
