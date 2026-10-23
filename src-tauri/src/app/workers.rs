use std::io;
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

    pub(crate) fn spawn<F>(&self, name: &str, worker: F) -> io::Result<()>
    where
        F: FnOnce(WorkerContext) + Send + 'static,
    {
        let mut handles = self.handles.lock().expect("worker registry lock poisoned");

        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "application runtime is shutting down",
            ));
        }

        let context = WorkerContext {
            shutdown_requested: Arc::clone(&self.shutdown_requested),
        };
        let handle = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || worker(context))?;

        handles.push(handle);
        Ok(())
    }

    pub(crate) fn active_count(&self) -> usize {
        self.handles
            .lock()
            .expect("worker registry lock poisoned")
            .len()
    }

    pub(crate) fn shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);

        let handles = {
            let mut handles = self.handles.lock().expect("worker registry lock poisoned");
            std::mem::take(&mut *handles)
        };

        for handle in handles {
            let _ = handle.join();
        }
    }
}

impl Default for WorkerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
