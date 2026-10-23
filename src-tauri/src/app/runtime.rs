use std::sync::Arc;

use eros::Context;

use super::{AppState, LifecycleState, WorkerContext, WorkerSupervisor};

#[derive(Clone)]
pub(crate) struct AppRuntime {
    state: Arc<AppState>,
    workers: Arc<WorkerSupervisor>,
}

#[allow(dead_code)]
impl AppRuntime {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(AppState::new()),
            workers: Arc::new(WorkerSupervisor::new()),
        }
    }

    pub(crate) fn start(&self) -> eros::Result<()> {
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

    pub(crate) fn shutdown(&self) -> eros::Result<()> {
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

    pub(crate) fn lifecycle(&self) -> eros::Result<LifecycleState> {
        self.state.lifecycle()
    }

    pub(crate) fn spawn_worker<F>(&self, name: &str, worker: F) -> eros::Result<()>
    where
        F: FnOnce(WorkerContext) + Send + 'static,
    {
        if self.lifecycle()? != LifecycleState::Ready {
            return Err(eros::error!("application runtime is not ready"));
        }

        self.workers.spawn(name, worker)
    }

    pub(crate) fn active_worker_count(&self) -> eros::Result<usize> {
        self.workers.active_count()
    }
}

impl Default for AppRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::thread;

    use super::*;

    #[test]
    fn runtime_starts_and_stops_without_webview() {
        let runtime = AppRuntime::new();

        assert_eq!(
            runtime.lifecycle().expect("read lifecycle"),
            LifecycleState::Created
        );
        runtime.start().expect("runtime should start");
        assert_eq!(
            runtime.lifecycle().expect("read lifecycle"),
            LifecycleState::Ready
        );

        runtime.shutdown().expect("runtime should shut down");
        assert_eq!(
            runtime.lifecycle().expect("read lifecycle"),
            LifecycleState::Stopped
        );
    }

    #[test]
    fn headless_runtime_accepts_backend_work_without_webview() {
        let runtime = AppRuntime::new();
        let worker_started = Arc::new(AtomicBool::new(false));
        let worker_started_in_worker = Arc::clone(&worker_started);

        runtime.start().expect("headless runtime should start");
        runtime
            .spawn_worker("headless-test-worker", move |context| {
                worker_started_in_worker.store(true, Ordering::Release);
                while !context.shutdown_requested() {
                    thread::yield_now();
                }
            })
            .expect("headless runtime should accept backend work");

        runtime.shutdown().expect("runtime should shut down");

        assert!(worker_started.load(Ordering::Acquire));
        assert_eq!(
            runtime.lifecycle().expect("read lifecycle"),
            LifecycleState::Stopped
        );
        assert_eq!(runtime.active_worker_count().expect("read worker count"), 0);
    }

    #[test]
    fn runtime_follows_explicit_startup_stages() {
        let runtime = AppRuntime::new();

        runtime
            .state
            .transition(LifecycleState::LoadingIdentity)
            .expect("identity stage should start");
        assert_eq!(
            runtime.lifecycle().expect("read lifecycle"),
            LifecycleState::LoadingIdentity
        );
        runtime
            .state
            .transition(LifecycleState::LoadingStore)
            .expect("store stage should start");
        runtime
            .state
            .transition(LifecycleState::StartingPlatform)
            .expect("platform stage should start");
        runtime
            .state
            .transition(LifecycleState::StartingDiscovery)
            .expect("discovery stage should start");
        runtime
            .state
            .transition(LifecycleState::Ready)
            .expect("ready stage should start");
        assert_eq!(
            runtime.lifecycle().expect("read lifecycle"),
            LifecycleState::Ready
        );
    }

    #[test]
    fn runtime_rejects_skipping_startup_stages() {
        let runtime = AppRuntime::new();

        let error = runtime
            .state
            .transition(LifecycleState::Ready)
            .expect_err("runtime must not skip initialization stages");
        let error = error
            .downcast_inner::<crate::app::InvalidTransition>()
            .expect("invalid transition should be preserved");
        assert_eq!(error.from, LifecycleState::Created);
        assert_eq!(error.to, LifecycleState::Ready);
    }

    #[test]
    fn shutdown_requests_workers_and_joins_them() {
        let runtime = AppRuntime::new();
        runtime.start().expect("runtime should start");
        let worker_stopped = Arc::new(AtomicBool::new(false));
        let worker_stopped_in_worker = Arc::clone(&worker_stopped);

        runtime
            .spawn_worker("test-worker", move |context| {
                while !context.shutdown_requested() {
                    thread::yield_now();
                }
                worker_stopped_in_worker.store(true, Ordering::Release);
            })
            .expect("worker should start");

        assert_eq!(runtime.active_worker_count().expect("read worker count"), 1);
        runtime.shutdown().expect("runtime should shut down");

        assert!(worker_stopped.load(Ordering::Acquire));
        assert_eq!(runtime.active_worker_count().expect("read worker count"), 0);
    }
}
