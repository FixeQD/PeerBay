//! Android platform adapters.

#[cfg(feature = "android-jni")]
pub(crate) const JNI_BACKEND: &str = "jni";

#[cfg(feature = "android-services")]
pub(crate) const SERVICES_BACKEND: &str = "android-services";

#[cfg(feature = "media")]
pub(crate) const MEDIA_BACKEND: &str = "media";

#[cfg(feature = "adb")]
pub(crate) const ADB_BACKEND: &str = "adb";

#[cfg(feature = "scrcpy")]
pub(crate) const SCRCPY_BACKEND: &str = "scrcpy";
