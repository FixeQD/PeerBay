use zeroize::Zeroizing;

use super::{errors::InMemoryTransportError, link::MemoryLink, transport::InMemoryTransport};
use crate::transport::{
    ChannelKind, PeerEndpoint, Transport, TransportChannel, TransportKind, TransportMetrics,
};

impl InMemoryTransport {
    pub fn accept(&self) -> eros::Result<Option<TransportChannel>> {
        let mut state = self.network.lock()?;
        let Some(channel_id) = state.links.iter().find_map(|(id, link)| {
            (link.remote_for(&self.local.device_id).is_some()
                && !link.accepted_by(&self.local.device_id))
            .then_some(id.clone())
        }) else {
            return Ok(None);
        };

        let link = state
            .links
            .get_mut(&channel_id)
            .ok_or_else(|| eros::error!(InMemoryTransportError::ChannelNotFound))?;
        link.mark_accepted(&self.local.device_id)?;
        Ok(Some(link.channel()))
    }

    pub fn send(&self, channel: &TransportChannel, payload: Vec<u8>) -> eros::Result<()> {
        let payload = Zeroizing::new(payload);
        if payload.len() > self.config.max_message_size {
            return Err(eros::error!(InMemoryTransportError::MessageTooLarge {
                length: payload.len(),
                max: self.config.max_message_size,
            }));
        }

        let mut state = self.network.lock()?;
        let link = state.link_for_mut(channel, &self.local.device_id)?;
        if link.closed {
            return Err(eros::error!(InMemoryTransportError::ChannelClosed));
        }
        if link.queued_bytes_from(&self.local.device_id) + payload.len()
            > self.config.max_queue_bytes
        {
            return Err(eros::error!(InMemoryTransportError::QueueFull {
                limit: self.config.max_queue_bytes,
            }));
        }
        link.enqueue(&self.local.device_id, payload)
    }

    pub fn receive(&self, channel: &TransportChannel) -> eros::Result<Option<Zeroizing<Vec<u8>>>> {
        let mut state = self.network.lock()?;
        let link = state.link_for_mut(channel, &self.local.device_id)?;
        if link.closed {
            return Ok(None);
        }
        link.dequeue(&self.local.device_id)
    }

    pub fn is_open(&self, channel: &TransportChannel) -> eros::Result<bool> {
        let state = self.network.lock()?;
        Ok(state
            .links
            .get(channel.id())
            .is_some_and(|link| !link.closed && link.has_peer(&self.local.device_id)))
    }

    fn open_link(
        &self,
        peer: &PeerEndpoint,
        channel: ChannelKind,
        transport: TransportKind,
    ) -> eros::Result<TransportChannel> {
        peer.validate()?;
        if peer.transport != self.kind() {
            return Err(eros::error!(InMemoryTransportError::WrongTransportKind {
                expected: self.kind(),
                received: peer.transport,
            }));
        }
        if !self.supports(channel) {
            return Err(eros::error!(InMemoryTransportError::UnsupportedChannel {
                channel
            }));
        }

        let mut state = self.network.lock()?;
        if peer.device_id == self.local.device_id {
            return Err(eros::error!(InMemoryTransportError::SelfConnection));
        }
        if !state.peers.contains_key(&peer.device_id) {
            return Err(eros::error!(InMemoryTransportError::PeerNotFound));
        }
        if state.peers.get(&peer.device_id) != Some(peer) {
            return Err(eros::error!(InMemoryTransportError::PeerEndpointMismatch));
        }

        let id = state.next_channel_id();
        let link = MemoryLink::new(
            self.local.device_id.clone(),
            peer.device_id.clone(),
            id.clone(),
            channel,
            transport,
            self.config,
        );
        state.links.insert(id.clone(), link);
        TransportChannel::new(id, transport, channel)
    }
}

impl Transport for InMemoryTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Loopback
    }

    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>> {
        let state = self.network.lock()?;
        Ok(state
            .peers
            .values()
            .filter(|peer| peer.device_id != self.local.device_id)
            .cloned()
            .collect())
    }

    fn open(&self, peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel> {
        self.open_link(peer, channel, self.kind())
    }

    fn close(&self, channel: &TransportChannel) -> eros::Result<()> {
        let mut state = self.network.lock()?;
        let link = state.link_for_mut(channel, &self.local.device_id)?;
        link.closed = true;
        link.clear();
        Ok(())
    }

    fn metrics(&self, channel: &TransportChannel) -> eros::Result<TransportMetrics> {
        let state = self.network.lock()?;
        let link = state.link_for(channel, &self.local.device_id)?;
        Ok(TransportMetrics::new(
            Some(0),
            None,
            link.queued_bytes_from(&self.local.device_id) as u64,
            link.closed,
        ))
    }

    fn supports(&self, _channel: ChannelKind) -> bool {
        true
    }

    fn migrate(
        &self,
        channel: &TransportChannel,
        target: TransportKind,
    ) -> eros::Result<TransportChannel> {
        let peer_id = {
            let state = self.network.lock()?;
            let link = state.link_for(channel, &self.local.device_id)?;
            if link.closed {
                return Err(eros::error!(InMemoryTransportError::ChannelClosed));
            }
            link.remote_for(&self.local.device_id)
                .ok_or_else(|| eros::error!(InMemoryTransportError::ChannelNotFound))?
                .to_owned()
        };
        let peer = {
            let state = self.network.lock()?;
            state
                .peers
                .get(&peer_id)
                .cloned()
                .ok_or_else(|| eros::error!(InMemoryTransportError::PeerNotFound))?
        };
        self.open_link(&peer, channel.kind(), target)
    }
}
