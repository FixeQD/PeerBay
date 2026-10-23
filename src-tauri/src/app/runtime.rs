use std::io;
use std::sync::Arc;

use super::{AppState, InvalidTransition, LifecycleState, WorkerContext, WorkerSupervisor};

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

    pub(crate) fn start(&self) -> Result<(), InvalidTransition> {
        self.state.transition(LifecycleState::LoadingIdentity)?;
        self.state.transition(LifecycleState::LoadingStore)?;
        self.state.transition(LifecycleState::StartingPlatform)?;
        self.state.transition(LifecycleState::StartingDiscovery)?;
        self.state.transition(LifecycleState::Ready)
    }

    pub(crate) fn shutdown(&self) {
        match self.state.lifecycle() {
            LifecycleState::Created => {
                let _ = self.state.transition(LifecycleState::ShuttingDown);
            }
            LifecycleState::LoadingIdentity
            | LifecycleState::LoadingStore
            | LifecycleState::StartingPlatform
            | LifecycleState::StartingDiscovery
            | LifecycleState::Ready => {
                let _ = self.state.transition(LifecycleState::ShuttingDown);
            }
            LifecycleState::ShuttingDown | LifecycleState::Stopped => {}
        }

        self.workers.shutdown();
        let _ = self.state.transition(LifecycleState::Stopped);
    }

    pub(crate) fn lifecycle(&self) -> LifecycleState {
        self.state.lifecycle()
    }

    pub(crate) fn spawn_worker<F>(&self, name: &str, worker: F) -> io::Result<()>
    where
        F: FnOnce(WorkerContext) + Send + 'static,
    {
        if self.lifecycle() != LifecycleState::Ready {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "application runtime is not ready",
            ));
        }

        self.workers.spawn(name, worker)
    }

    pub(crate) fn active_worker_count(&self) -> usize {
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

        assert_eq!(runtime.lifecycle(), LifecycleState::Created);
        runtime.start().expect("runtime should start");
        assert_eq!(runtime.lifecycle(), LifecycleState::Ready);

        runtime.shutdown();
        assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
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

        runtime.shutdown();

        assert!(worker_started.load(Ordering::Acquire));
        assert_eq!(runtime.lifecycle(), LifecycleState::Stopped);
        assert_eq!(runtime.active_worker_count(), 0);
    }

    #[test]
    fn runtime_follows_explicit_startup_stages() {
        let runtime = AppRuntime::new();

        runtime
            .state
            .transition(LifecycleState::LoadingIdentity)
            .expect("identity stage should start");
        assert_eq!(runtime.lifecycle(), LifecycleState::LoadingIdentity);
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
        assert_eq!(runtime.lifecycle(), LifecycleState::Ready);
    }

    #[test]
    fn runtime_rejects_skipping_startup_stages() {
        let runtime = AppRuntime::new();

        let error = runtime
            .state
            .transition(LifecycleState::Ready)
            .expect_err("runtime must not skip initialization stages");
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

        assert_eq!(runtime.active_worker_count(), 1);
        runtime.shutdown();

        assert!(worker_stopped.load(Ordering::Acquire));
        assert_eq!(runtime.active_worker_count(), 0);
    }
}
