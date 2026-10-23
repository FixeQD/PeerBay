use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct WorkerContext {
    shutdown_requested: Arc<AtomicBool>,
}

#[allow(dead_code)]
impl WorkerContext {
    pub(crate) fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }
}

#[allow(dead_code)]
pub(crate) struct WorkerSupervisor {
    shutdown_requested: Arc<AtomicBool>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

#[allow(dead_code)]
impl WorkerSupervisor {
    pub(crate) fn new() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            handles: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn spawn<F>(&self, name: &str, worker: F) -> eros::Result<()>
    where
        F: FnOnce(WorkerContext) + Send + 'static,
    {
        let mut handles = self.handles.lock().map_err(|_| {
            eros::error!("worker registry lock poisoned").context("register worker")
        })?;

        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(eros::error!("application runtime is shutting down"));
        }

        let context = WorkerContext {
            shutdown_requested: Arc::clone(&self.shutdown_requested),
        };
        let handle = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || worker(context))
            .map_err(|error| eros::error!(error).context("spawn worker thread"))?;

        handles.push(handle);
        Ok(())
    }

    pub(crate) fn active_count(&self) -> eros::Result<usize> {
        self.handles
            .lock()
            .map(|handles| handles.len())
            .map_err(|_| eros::error!("worker registry lock poisoned").context("count workers"))
    }

    pub(crate) fn shutdown(&self) -> eros::Result<()> {
        self.shutdown_requested.store(true, Ordering::Release);

        let handles = {
            let mut handles = self.handles.lock().map_err(|_| {
                eros::error!("worker registry lock poisoned").context("stop workers")
            })?;
            std::mem::take(&mut *handles)
        };

        let mut worker_panicked = false;
        for handle in handles {
            if handle.join().is_err() {
                worker_panicked = true;
            }
        }

        if worker_panicked {
            return Err(eros::error!("application worker panicked").context("join workers"));
        }

        Ok(())
    }
}

impl Default for WorkerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
