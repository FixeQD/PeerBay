//! Android platform adapters.

use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AndroidHostLifecycle {
    Created,
    Resumed,
    Paused,
    Destroyed,
}

impl AndroidHostLifecycle {
    fn can_transition(self, next: Self) -> bool {
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
pub(crate) struct AndroidBridgeSnapshot {
    pub(crate) lifecycle: AndroidHostLifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InvalidAndroidLifecycleTransition {
    pub(crate) from: AndroidHostLifecycle,
    pub(crate) to: AndroidHostLifecycle,
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
pub(crate) struct AndroidBridgeState {
    snapshot: Arc<RwLock<AndroidBridgeSnapshot>>,
}

impl AndroidBridgeState {
    pub(crate) fn new() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(AndroidBridgeSnapshot {
                lifecycle: AndroidHostLifecycle::Created,
            })),
        }
    }

    pub(crate) fn snapshot(&self) -> AndroidBridgeSnapshot {
        *self
            .snapshot
            .read()
            .expect("Android bridge state lock poisoned")
    }

    pub(crate) fn transition(
        &self,
        next: AndroidHostLifecycle,
    ) -> Result<(), InvalidAndroidLifecycleTransition> {
        let mut snapshot = self
            .snapshot
            .write()
            .expect("Android bridge state lock poisoned");

        if !snapshot.lifecycle.can_transition(next) {
            return Err(InvalidAndroidLifecycleTransition {
                from: snapshot.lifecycle,
                to: next,
            });
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

#[cfg(test)]
mod tests {
    use super::{AndroidBridgeState, AndroidHostLifecycle};

    #[test]
    fn bridge_state_tracks_native_host_lifecycle() {
        let state = AndroidBridgeState::new();
        assert_eq!(state.snapshot().lifecycle, AndroidHostLifecycle::Created);

        state
            .transition(AndroidHostLifecycle::Resumed)
            .expect("created host should resume");
        state
            .transition(AndroidHostLifecycle::Paused)
            .expect("resumed host should pause");
        state
            .transition(AndroidHostLifecycle::Destroyed)
            .expect("paused host should be destroyable");
        assert_eq!(state.snapshot().lifecycle, AndroidHostLifecycle::Destroyed);
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
