use std::sync::Arc;

use eros::Context;

use crate::identity::DeviceIdentity;

use super::{AppState, LifecycleState, WorkerContext, WorkerSupervisor};

#[derive(Clone)]
pub struct AppRuntime {
    state: Arc<AppState>,
    workers: Arc<WorkerSupervisor>,
    identity: Arc<DeviceIdentity>,
}

#[allow(dead_code)]
impl AppRuntime {
    pub fn new() -> Self {
        Self {
            state: Arc::new(AppState::new()),
            workers: Arc::new(WorkerSupervisor::new()),
            identity: Arc::new(DeviceIdentity::generate()),
        }
    }

    pub fn identity(&self) -> DeviceIdentity {
        self.identity.as_ref().clone()
    }

    pub fn start(&self) -> eros::Result<()> {
        self.state
            .transition(LifecycleState::LoadingIdentity)
            .context("load application identity")?;
        self.state
            .transition(LifecycleState::LoadingStore)
            .context("load application store")?;
        self.state
            .transition(LifecycleState::StartingPlatform)
            .context("start platform ports")?;
        self.state
            .transition(LifecycleState::StartingDiscovery)
            .context("start discovery")?;
        self.state
            .transition(LifecycleState::Ready)
            .context("mark runtime ready")
    }

    pub fn shutdown(&self) -> eros::Result<()> {
        match self.state.lifecycle()? {
            LifecycleState::Created => {
                self.state.transition(LifecycleState::ShuttingDown)?;
            }
            LifecycleState::LoadingIdentity
            | LifecycleState::LoadingStore
            | LifecycleState::StartingPlatform
            | LifecycleState::StartingDiscovery
            | LifecycleState::Ready => {
                self.state.transition(LifecycleState::ShuttingDown)?;
            }
            LifecycleState::ShuttingDown | LifecycleState::Stopped => {}
        }

        self.workers
            .shutdown()
            .context("stop application workers")?;
        self.state
            .transition(LifecycleState::Stopped)
            .context("mark runtime stopped")
    }

    pub fn lifecycle(&self) -> eros::Result<LifecycleState> {
        self.state.lifecycle()
    }

    pub fn transition(&self, next: LifecycleState) -> eros::Result<()> {
        self.state.transition(next)
    }

    pub fn spawn_worker<F>(&self, name: &str, worker: F) -> eros::Result<()>
    where
        F: FnOnce(WorkerContext) + Send + 'static,
    {
        if self.lifecycle()? != LifecycleState::Ready {
            return Err(eros::error!("application runtime is not ready"));
        }

        self.workers.spawn(name, worker)
    }

    pub fn active_worker_count(&self) -> eros::Result<usize> {
        self.workers.active_count()
    }
}

impl Default for AppRuntime {
    fn default() -> Self {
        Self::new()
    }
}
