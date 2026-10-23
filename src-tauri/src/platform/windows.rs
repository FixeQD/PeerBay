//! Windows platform adapters.

#[cfg(feature = "windows-win32")]
pub(crate) const WIN32_BACKEND: &str = "win32";

#[cfg(feature = "windows-winrt")]
pub(crate) const WINRT_BACKEND: &str = "winrt";

#[cfg(feature = "windows-wifi-direct")]
pub(crate) const WIFI_DIRECT_BACKEND: &str = "wifi-direct";
