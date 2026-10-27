use super::{config::InMemoryConfig, errors::InMemoryTransportError, network::InMemoryNetwork};
use crate::transport::{PeerEndpoint, TransportKind};

#[derive(Clone)]
pub struct InMemoryTransport {
    pub(super) local: PeerEndpoint,
    pub(super) network: InMemoryNetwork,
    pub(super) config: InMemoryConfig,
}

impl InMemoryTransport {
    pub fn new(local: PeerEndpoint) -> eros::Result<Self> {
        Self::with_network(InMemoryNetwork::new(), local)
    }

    pub fn with_network(network: InMemoryNetwork, local: PeerEndpoint) -> eros::Result<Self> {
        Self::with_network_and_config(network, local, InMemoryConfig::default())
    }

    pub fn with_network_and_config(
        network: InMemoryNetwork,
        local: PeerEndpoint,
        config: InMemoryConfig,
    ) -> eros::Result<Self> {
        local.validate()?;
        config.validate()?;
        if local.transport != TransportKind::Loopback {
            return Err(eros::error!(InMemoryTransportError::WrongTransportKind {
                expected: TransportKind::Loopback,
                received: local.transport,
            }));
        }

        let mut state = network.lock()?;
        if state
            .peers
            .insert(local.device_id.clone(), local.clone())
            .is_some()
        {
            return Err(eros::error!(InMemoryTransportError::DuplicatePeer));
        }
        drop(state);

        Ok(Self {
            local,
            network,
            config,
        })
    }

    pub fn pair(first: PeerEndpoint, second: PeerEndpoint) -> eros::Result<(Self, Self)> {
        Self::pair_with_config(first, second, InMemoryConfig::default())
    }

    pub fn pair_with_config(
        first: PeerEndpoint,
        second: PeerEndpoint,
        config: InMemoryConfig,
    ) -> eros::Result<(Self, Self)> {
        let network = InMemoryNetwork::new();
        let first_transport = Self::with_network_and_config(network.clone(), first, config)?;
        let second_transport = Self::with_network_and_config(network, second, config)?;
        Ok((first_transport, second_transport))
    }

    pub fn local_endpoint(&self) -> &PeerEndpoint {
        &self.local
    }

    pub const fn config(&self) -> InMemoryConfig {
        self.config
    }
}
