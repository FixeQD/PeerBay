use super::FlakyConfig;
use crate::transport::{
    ChannelKind, PeerEndpoint, Transport, TransportChannel, TransportKind, TransportMetrics,
};

pub struct FlakyTransport<T: Transport> {
    inner: T,
    config: FlakyConfig,
}

impl<T: Transport> FlakyTransport<T> {
    pub fn new(inner: T, config: FlakyConfig) -> Self {
        Self { inner, config }
    }
}

impl<T: Transport + Clone> Transport for FlakyTransport<T> {
    fn kind(&self) -> TransportKind {
        self.inner.kind()
    }

    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>> {
        self.inner.discover()
    }

    fn open(&self, peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel> {
        self.inner.open(peer, channel)
    }

    fn close(&self, channel: &TransportChannel) -> eros::Result<()> {
        self.inner.close(channel)
    }

    fn metrics(&self, channel: &TransportChannel) -> eros::Result<TransportMetrics> {
        let mut metrics = self.inner.metrics(channel)?;
        if self.config.bandwidth_bytes.is_some() {
            metrics.throughput_bytes_per_second = self.config.bandwidth_bytes;
        }
        metrics.degraded =
            metrics.degraded || self.config.drop_rate > 0.0 || self.config.delay_ms > 0;
        Ok(metrics)
    }

    fn supports(&self, channel: ChannelKind) -> bool {
        self.inner.supports(channel)
    }

    fn migrate(
        &self,
        channel: &TransportChannel,
        target: TransportKind,
    ) -> eros::Result<TransportChannel> {
        self.inner.migrate(channel, target)
    }
}
