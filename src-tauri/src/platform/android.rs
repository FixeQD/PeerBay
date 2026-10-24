//! Android platform adapters.

use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AndroidHostLifecycle {
    Created,
    Resumed,
    Paused,
    Destroyed,
}

impl AndroidHostLifecycle {
    pub fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Created,
                Self::Resumed | Self::Paused | Self::Destroyed
            ) | (Self::Resumed, Self::Paused | Self::Destroyed)
                | (Self::Paused, Self::Resumed | Self::Destroyed)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndroidBridgeSnapshot {
    pub lifecycle: AndroidHostLifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidAndroidLifecycleTransition {
    pub from: AndroidHostLifecycle,
    pub to: AndroidHostLifecycle,
}

impl Display for InvalidAndroidLifecycleTransition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid Android host lifecycle transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for InvalidAndroidLifecycleTransition {}

/// Rust-owned state boundary for the generated Android host and future JNI or service adapters
#[derive(Clone)]
pub struct AndroidBridgeState {
    snapshot: Arc<RwLock<AndroidBridgeSnapshot>>,
}

impl AndroidBridgeState {
    pub fn new() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(AndroidBridgeSnapshot {
                lifecycle: AndroidHostLifecycle::Created,
            })),
        }
    }

    pub fn snapshot(&self) -> eros::Result<AndroidBridgeSnapshot> {
        Ok(*self.snapshot.read().map_err(|_| {
            eros::error!("Android bridge state lock poisoned").context("read Android bridge state")
        })?)
    }

    pub fn transition(&self, next: AndroidHostLifecycle) -> eros::Result<()> {
        let mut snapshot = self.snapshot.write().map_err(|_| {
            eros::error!("Android bridge state lock poisoned").context("write Android bridge state")
        })?;

        if !snapshot.lifecycle.can_transition(next) {
            return Err(eros::error!(InvalidAndroidLifecycleTransition {
                from: snapshot.lifecycle,
                to: next,
            })
            .context("advance Android host lifecycle"));
        }

        snapshot.lifecycle = next;
        Ok(())
    }
}

impl Default for AndroidBridgeState {
    fn default() -> Self {
        Self::new()
    }
}

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
