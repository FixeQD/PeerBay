use peerbay_lib::transport::{ChannelKind, InMemoryTransport, PeerEndpoint};
use peerbay_lib::transport::{FlakyConfig, FlakyTransport, Transport, TransportKind};

fn endpoint(id: &str) -> PeerEndpoint {
    PeerEndpoint::new(id, format!("memory://{}", id), TransportKind::Loopback).unwrap()
}

#[test]
fn flaky_transport_simulates_delay_drop_reorder_and_bandwidth() {
    let config = FlakyConfig {
        drop_rate: 0.1,
        delay_ms: 10,
        reorder_rate: 0.05,
        duplicate_rate: 0.05,
        bandwidth_bytes: Some(1024),
    };
    let (inner_a, inner_b) =
        InMemoryTransport::pair(endpoint("peer-flaky-x"), endpoint("peer-flaky-y")).unwrap();
    drop(inner_b);
    let flaky = FlakyTransport::new(inner_a, config);
    assert!(flaky.supports(ChannelKind::Control));
    assert_eq!(flaky.kind(), TransportKind::Loopback);
    let channel = flaky
        .open(&endpoint("peer-flaky-y"), ChannelKind::Control)
        .unwrap();
    let metrics = flaky.metrics(&channel).unwrap();
    assert!(metrics.degraded);
    assert_eq!(metrics.throughput_bytes_per_second, Some(1024));
}
