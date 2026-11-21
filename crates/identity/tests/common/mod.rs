#![allow(dead_code)]

use identity::{DeviceIdentityError, IdentityKeyStoreError};

pub const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
pub const PRIVATE_KEY_BYTES: [u8; 32] = [7; 32];

pub fn identity_error(result: eros::Result<()>) -> DeviceIdentityError {
    result
        .expect_err("identity validation should fail")
        .downcast_inner::<DeviceIdentityError>()
        .expect("identity error should be preserved")
}

pub fn key_store_error(result: eros::Result<()>) -> IdentityKeyStoreError {
    result
        .expect_err("key store operation should fail")
        .downcast_inner::<IdentityKeyStoreError>()
        .expect("key store error should be preserved")
}
