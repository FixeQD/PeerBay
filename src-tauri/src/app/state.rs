use std::sync::RwLock;

use super::{InvalidTransition, LifecycleState};

pub(crate) struct AppState {
    lifecycle: RwLock<LifecycleState>,
}

impl AppState {
    pub(crate) fn new() -> Self {
        Self {
            lifecycle: RwLock::new(LifecycleState::Created),
        }
    }

    pub(crate) fn lifecycle(&self) -> eros::Result<LifecycleState> {
        self.lifecycle
            .read()
            .map(|lifecycle| *lifecycle)
            .map_err(|_| {
                eros::error!("application lifecycle lock poisoned").context("read app state")
            })
    }

    pub(crate) fn transition(&self, next: LifecycleState) -> eros::Result<()> {
        let mut current = self.lifecycle.write().map_err(|_| {
            eros::error!("application lifecycle lock poisoned").context("write app state")
        })?;

        if !current.can_transition(next) {
            return Err(eros::error!(InvalidTransition {
                from: *current,
                to: next,
            })
            .context("advance application lifecycle"));
        }

        *current = next;
        Ok(())
    }
}
