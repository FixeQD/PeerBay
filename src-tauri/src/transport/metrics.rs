#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransportMetrics {
    pub rtt_ms: Option<u32>,
    pub throughput_bytes_per_second: Option<u64>,
    pub queued_bytes: u64,
    pub degraded: bool,
}

impl TransportMetrics {
    pub const fn new(
        rtt_ms: Option<u32>,
        throughput_bytes_per_second: Option<u64>,
        queued_bytes: u64,
        degraded: bool,
    ) -> Self {
        Self {
            rtt_ms,
            throughput_bytes_per_second,
            queued_bytes,
            degraded,
        }
    }
}
