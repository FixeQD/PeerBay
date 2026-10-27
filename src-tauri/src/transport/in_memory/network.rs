use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use super::{errors::InMemoryTransportError, link::MemoryLink};
use crate::transport::{PeerEndpoint, TransportChannel};

#[derive(Clone, Default)]
pub struct InMemoryNetwork {
    pub(super) state: Arc<Mutex<NetworkState>>,
}

impl InMemoryNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn lock(&self) -> eros::Result<MutexGuard<'_, NetworkState>> {
        self.state
            .lock()
            .map_err(|_| eros::error!(InMemoryTransportError::NetworkPoisoned))
    }
}

pub(super) struct NetworkState {
    pub(super) peers: BTreeMap<String, PeerEndpoint>,
    pub(super) links: BTreeMap<String, MemoryLink>,
    next_channel: u64,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self {
            peers: BTreeMap::new(),
            links: BTreeMap::new(),
            next_channel: 1,
        }
    }
}

impl NetworkState {
    pub(super) fn next_channel_id(&mut self) -> String {
        let id = format!("memory-channel-{:016}", self.next_channel);
        self.next_channel = self.next_channel.saturating_add(1);
        id
    }

    pub(super) fn link_for(
        &self,
        channel: &TransportChannel,
        local_device_id: &str,
    ) -> eros::Result<&MemoryLink> {
        let link = self
            .links
            .get(channel.id())
            .ok_or_else(|| eros::error!(InMemoryTransportError::ChannelNotFound))?;
        if !link.has_peer(local_device_id)
            || link.kind != channel.kind()
            || link.transport != channel.transport()
        {
            return Err(eros::error!(InMemoryTransportError::ChannelNotFound));
        }
        Ok(link)
    }

    pub(super) fn link_for_mut(
        &mut self,
        channel: &TransportChannel,
        local_device_id: &str,
    ) -> eros::Result<&mut MemoryLink> {
        let link = self
            .links
            .get_mut(channel.id())
            .ok_or_else(|| eros::error!(InMemoryTransportError::ChannelNotFound))?;
        if !link.has_peer(local_device_id)
            || link.kind != channel.kind()
            || link.transport != channel.transport()
        {
            return Err(eros::error!(InMemoryTransportError::ChannelNotFound));
        }
        Ok(link)
    }
}
