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

    pub(crate) fn lifecycle(&self) -> LifecycleState {
        *self
            .lifecycle
            .read()
            .expect("application lifecycle lock poisoned")
    }

    pub(crate) fn transition(&self, next: LifecycleState) -> Result<(), InvalidTransition> {
        let mut current = self
            .lifecycle
            .write()
            .expect("application lifecycle lock poisoned");

        if !current.can_transition(next) {
            return Err(InvalidTransition {
                from: *current,
                to: next,
            });
        }

        *current = next;
        Ok(())
    }
}
