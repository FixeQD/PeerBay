use std::sync::{Arc, RwLock};

use eros::Context;

use crate::identity::{DeviceIdentity, IdentityKeyPair, IdentityKeyStore, TransportCertificate};

use super::{AppState, LifecycleState, WorkerContext, WorkerSupervisor};

#[derive(Clone)]
pub struct AppRuntime {
    state: Arc<AppState>,
    workers: Arc<WorkerSupervisor>,
    identity: Arc<DeviceIdentity>,
    identity_keys: Arc<RwLock<IdentityKeyStore>>,
    transport_certificate: Arc<TransportCertificate>,
}

#[allow(dead_code)]
impl AppRuntime {
    pub fn new() -> Self {
        Self::try_new().expect("PeerBay runtime identity initialization should succeed")
    }

    pub fn try_new() -> eros::Result<Self> {
        let identity = Arc::new(DeviceIdentity::generate());
        let transport_certificate = Arc::new(TransportCertificate::generate_for_device(
            identity.device_id(),
        )?);

        Ok(Self {
            state: Arc::new(AppState::new()),
            workers: Arc::new(WorkerSupervisor::new()),
            identity,
            identity_keys: Arc::new(RwLock::new(IdentityKeyStore::generated())),
            transport_certificate,
        })
    }

    pub fn transport_certificate(&self) -> Arc<TransportCertificate> {
        Arc::clone(&self.transport_certificate)
    }

    pub fn identity(&self) -> DeviceIdentity {
        self.identity.as_ref().clone()
    }

    pub fn identity_public_key(&self) -> eros::Result<[u8; 32]> {
        let store = self.identity_keys.read().map_err(|_| {
            eros::error!("identity key store lock poisoned").context("read identity key store")
        })?;
        Ok(store.load()?.public_key_bytes())
    }

    pub fn with_identity_private_key<R>(
        &self,
        callback: impl FnOnce(&[u8; 32]) -> R,
    ) -> eros::Result<R> {
        let store = self.identity_keys.read().map_err(|_| {
            eros::error!("identity key store lock poisoned").context("read identity key store")
        })?;
        Ok(store.load()?.with_private_key(callback))
    }

    pub fn replace_identity_keypair(&self, keypair: IdentityKeyPair) -> eros::Result<()> {
        let mut store = self.identity_keys.write().map_err(|_| {
            eros::error!("identity key store lock poisoned").context("write identity key store")
        })?;
        store.save(keypair);
        Ok(())
    }

    pub fn clear_identity_keypair(&self) -> eros::Result<()> {
        let mut store = self.identity_keys.write().map_err(|_| {
            eros::error!("identity key store lock poisoned").context("write identity key store")
        })?;
        store.clear();
        Ok(())
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
