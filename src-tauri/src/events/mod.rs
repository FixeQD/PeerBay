//! Backend events exposed through the Tauri bridge.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EventName {
    AppLifecycle,
}

impl EventName {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AppLifecycle => "app.lifecycle",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct LifecyclePayload {
    pub(crate) state: &'static str,
}

impl LifecyclePayload {
    pub(crate) const fn ready() -> Self {
        Self { state: "ready" }
    }
}
