use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use super::{config::TcpTransportConfig, errors::TcpTransportError, state::TcpTransportState};
use crate::transport::{PeerEndpoint, TransportKind};

#[derive(Clone)]
pub struct TcpTransport {
    pub(crate) local: PeerEndpoint,
    pub(crate) config: TcpTransportConfig,
    pub(crate) listener: Arc<TcpListener>,
    pub(crate) state: Arc<Mutex<TcpTransportState>>,
}

impl TcpTransport {
    pub fn new(local: PeerEndpoint) -> eros::Result<Self> {
        Self::with_config(local, TcpTransportConfig::default())
    }

    pub fn with_config(local: PeerEndpoint, config: TcpTransportConfig) -> eros::Result<Self> {
        local.validate()?;
        config.validate()?;
        if local.transport != TransportKind::Loopback {
            return Err(eros::error!(TcpTransportError::WrongTransportKind {
                expected: TransportKind::Loopback,
                received: local.transport,
            }));
        }
        let address: SocketAddr = local
            .address
            .parse()
            .map_err(|_| eros::error!(TcpTransportError::InvalidLocalAddress))?;
        let listener = TcpListener::bind(address).map_err(|_| {
            eros::error!(TcpTransportError::BindFailed {
                address: local.address.clone(),
            })
        })?;
        listener.set_nonblocking(true).map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "configure listener"
            })
        })?;

        Ok(Self {
            local,
            config,
            listener: Arc::new(listener),
            state: Arc::new(Mutex::new(TcpTransportState::new())),
        })
    }

    pub fn pair(first: PeerEndpoint, second: PeerEndpoint) -> eros::Result<(Self, Self)> {
        Self::pair_with_config(first, second, TcpTransportConfig::default())
    }

    pub fn pair_with_config(
        first: PeerEndpoint,
        second: PeerEndpoint,
        config: TcpTransportConfig,
    ) -> eros::Result<(Self, Self)> {
        let first_transport = Self::with_config(first, config)?;
        let second_transport = Self::with_config(second, config)?;
        Ok((first_transport, second_transport))
    }

    pub fn local_endpoint(&self) -> &PeerEndpoint {
        &self.local
    }

    pub fn config(&self) -> TcpTransportConfig {
        self.config
    }

    pub fn listener_address(&self) -> eros::Result<String> {
        self.listener
            .local_addr()
            .map(|address| address.to_string())
            .map_err(|_| {
                eros::error!(TcpTransportError::Io {
                    operation: "listener address"
                })
            })
    }
}
