//! Platform-port boundary.

#[allow(dead_code)]
mod capability;
#[allow(dead_code)]
mod mock;
#[allow(dead_code)]
mod ports;

#[cfg(target_os = "android")]
#[allow(dead_code)]
mod android;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod linux;
#[cfg(target_os = "windows")]
#[allow(dead_code)]
mod windows;

pub(crate) use capability::PlatformDescriptor;

#[cfg(target_os = "android")]
pub(crate) use android::AndroidBridgeState;
