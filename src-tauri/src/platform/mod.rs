//! Platform-port boundary.

#[allow(dead_code)]
pub mod capability;
#[allow(dead_code)]
mod mock;
#[allow(dead_code)]
pub mod ports;

#[cfg(target_os = "android")]
#[allow(dead_code)]
pub mod android;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod linux;
#[cfg(target_os = "windows")]
#[allow(dead_code)]
mod windows;

pub use capability::{PlatformDescriptor, PlatformTarget};

#[cfg(target_os = "android")]
pub use android::{AndroidBridgeState, AndroidHostLifecycle};
