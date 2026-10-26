use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::task::JoinHandle;

#[derive(Clone)]
#[allow(dead_code)]
pub struct WorkerContext {
    shutdown_requested: Arc<AtomicBool>,
}

impl WorkerContext {
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire)
    }
}

pub struct WorkerSupervisor {
    shutdown_requested: Arc<AtomicBool>,
    handles: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl WorkerSupervisor {
    pub fn new() -> Self {
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            handles: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub async fn spawn<F>(&self, _name: &str, worker: F) -> eros::Result<()>
    where
        F: FnOnce(WorkerContext) + Send + 'static,
    {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(eros::error!("application runtime is shutting down"));
        }
        let context = WorkerContext {
            shutdown_requested: Arc::clone(&self.shutdown_requested),
        };
        let handle = tokio::spawn(async move { worker(context) });
        let mut handles = self.handles.lock().await;
        handles.push(handle);
        Ok(())
    }

    pub async fn active_count(&self) -> eros::Result<usize> {
        let handles = self.handles.lock().await;
        Ok(handles.len())
    }

    pub async fn shutdown(&self) -> eros::Result<()> {
        self.shutdown_requested.store(true, Ordering::Release);
        let mut handles = self.handles.lock().await;
        let taken = std::mem::take(&mut *handles);
        drop(handles);
        for handle in taken {
            let _ = handle.await;
        }
        Ok(())
    }
}

impl Default for WorkerSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
