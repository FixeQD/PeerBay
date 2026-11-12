use super::{ChannelKind, PeerEndpoint, TransportChannel, TransportKind, TransportMetrics};
use zeroize::Zeroizing;

pub trait Transport: Send + Sync {
    fn kind(&self) -> TransportKind;
    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>>;
    fn open(&self, peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel>;
    fn close(&self, channel: &TransportChannel) -> eros::Result<()>;
    fn send(&self, channel: &TransportChannel, payload: Vec<u8>) -> eros::Result<()>;
    fn receive(&self, channel: &TransportChannel) -> eros::Result<Option<Zeroizing<Vec<u8>>>>;
    fn metrics(&self, channel: &TransportChannel) -> eros::Result<TransportMetrics>;
    fn supports(&self, channel: ChannelKind) -> bool;

    fn can_connect(&self, peer: &PeerEndpoint) -> bool {
        peer.transport == self.kind() && peer.validate().is_ok()
    }

    fn migrate(
        &self,
        channel: &TransportChannel,
        target: TransportKind,
    ) -> eros::Result<TransportChannel>;
}
